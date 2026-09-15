package main

// New WAN links (D-070) and ISP names (D-071).
//
// A link nothing has claimed is probed by omp-wan-probe, in a namespace of
// its own, for DHCP and then the internet. One with both is shown on the Home
// tab as a new WAN link, and becomes one only when the owner says so: its
// netplan, its WireGuard transport, and a daemon restart to take it on as a
// path. Home is told the new transport's key by ompd itself.
//
// Every link's ISP is looked up at ipinfo.io through that link - its socket
// carries the link's fwmark, so the answer names the link's own egress - when
// the link comes up and every few hours after, and kept for ompd to name the
// paths by.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/lan"
	"github.com/anthonysecco/OpenMultiPath/internal/state"
	"github.com/anthonysecco/OpenMultiPath/internal/wan"
)

const (
	wanScanInterval = 15 * time.Second
	ispPollInterval = 30 * time.Second
	// ispMaxAge is how long an ISP name is trusted without a fresh look. A
	// link's ISP does not change, but what sits behind a port can.
	ispMaxAge = 6 * time.Hour
	// ispMinGap stops a flapping link from being looked up every time it
	// comes back; ipinfo.io's free tier is not ours to spend carelessly.
	ispMinGap = 5 * time.Minute
)

type wanManager struct {
	candPath   string
	ispPath    string
	lanPath    string
	statePath  string
	probeCmd   string
	wgDir      string
	netplanDir string
	daemonUnit string
	ipinfoURL  string

	run func(env []string, name string, args ...string) ([]byte, error)

	// treatAsHardware names interfaces to consider even though the kernel
	// names no device behind them - a veth standing in for a NIC, in testing.
	treatAsHardware map[string]bool

	mu        sync.Mutex
	probing   string // the interface being probed, "" for none
	lastAlive map[string]bool
	lastISP   map[string]time.Time
}

func newWANManager(statePath, lanPath, unit string) *wanManager {
	return &wanManager{
		candPath:   wan.DefaultCandidatesPath,
		ispPath:    wan.DefaultISPPath,
		lanPath:    lanPath,
		statePath:  statePath,
		probeCmd:   "omp-wan-probe",
		wgDir:      "/etc/wireguard",
		netplanDir: "/etc/netplan",
		daemonUnit: unit,
		ipinfoURL:  "https://ipinfo.io/json",
		run: func(env []string, name string, args ...string) ([]byte, error) {
			cmd := exec.Command(name, args...)
			cmd.Env = append(os.Environ(), env...)
			return cmd.CombinedOutput()
		},
		lastAlive: map[string]bool{},
		lastISP:   map[string]time.Time{},
	}
}

// start recovers from an ompui that died mid-probe or mid-add, then runs the
// scanner and the ISP refresher.
func (m *wanManager) start() {
	if out, err := m.run(nil, "ip", "netns", "list"); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			ns := strings.Fields(line)
			if len(ns) > 0 && strings.HasPrefix(ns[0], "omp-probe-") {
				iface := strings.TrimPrefix(ns[0], "omp-probe-")
				log.Printf("ompui: returning %s from a probe that did not finish", iface)
				m.run(nil, "ip", "-n", ns[0], "link", "set", iface, "netns", "1")
				m.run(nil, "ip", "netns", "del", ns[0])
			}
		}
	}
	m.update(func(f *wan.CandidatesFile) {
		for name, c := range f.Links {
			switch c.State {
			case wan.Probing:
				delete(f.Links, name) // probed again from scratch
			case wan.Adding:
				c.State, c.Detail = wan.AddFailed, "interrupted: ompui restarted while adding it"
				f.Links[name] = c
			}
		}
	})
	go func() {
		for {
			m.scan()
			time.Sleep(wanScanInterval)
		}
	}()
	go func() {
		for {
			m.refreshISPs()
			time.Sleep(ispPollInterval)
		}
	}()
}

// peek reads one candidate without changing anything.
func (m *wanManager) peek(iface string) (wan.Candidate, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, _ := wan.LoadCandidates(m.candPath)
	c, ok := f.Links[iface]
	return c, ok
}

// update loads, changes and saves the candidates file under the lock.
func (m *wanManager) update(fn func(*wan.CandidatesFile)) wan.CandidatesFile {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, err := wan.LoadCandidates(m.candPath)
	if err != nil {
		log.Printf("ompui: %v; starting the new-link record over", err)
	}
	fn(&f)
	if err := wan.SaveCandidates(m.candPath, f); err != nil {
		log.Printf("ompui: saving new-link record: %v", err)
	}
	return f
}

func (m *wanManager) links() []wan.Link {
	sys, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []wan.Link
	for _, i := range sys {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		l := wan.Link{
			Name:           i.Name,
			MAC:            i.HardwareAddr.String(),
			Up:             i.Flags&net.FlagUp != 0,
			Carrier:        readSys(i.Name, "carrier") == 1,
			CarrierChanges: readSys(i.Name, "carrier_changes"),
			Hardware:       hasDevice(i.Name) || m.treatAsHardware[i.Name],
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLinkLocalUnicast() {
				l.HasIPv4 = true
			}
		}
		out = append(out, l)
	}
	return out
}

// configuredElsewhere maps each interface some netplan file names to that
// file. A WAN link added here is in its own file, so it is claimed too.
func (m *wanManager) configuredElsewhere(names []string) map[string]string {
	out := map[string]string{}
	files, _ := filepath.Glob(filepath.Join(m.netplanDir, "*.yaml"))
	for _, file := range files {
		if filepath.Base(file) == filepath.Base(lan.NetplanPath) {
			continue // the LAN tab's file; its interfaces are LANs
		}
		b, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		for _, n := range names {
			if regexp.MustCompile(`(?m)^\s+` + regexp.QuoteMeta(n) + `:\s*$`).Match(b) {
				out[n] = file
			}
		}
	}
	return out
}

func (m *wanManager) scan() {
	links := m.links()
	names := make([]string, len(links))
	for i, l := range links {
		names[i] = l.Name
	}
	lans := map[string]bool{}
	if f, err := lan.Load(m.lanPath); err == nil {
		for _, s := range f.Segments {
			lans[s.Interface] = true
		}
	}
	configured := m.configuredElsewhere(names)
	now := time.Now().Unix()

	// A new NIC arrives administratively down, and a down link has no carrier
	// to read, so an unclaimed one is brought up to find out whether anything
	// is plugged into it. IPv6 goes off first: the kernel accepts router
	// advertisements by default, and an interface brought up with it on would
	// take a default route out of a link nobody has approved (D-026).
	for i, l := range links {
		if l.Up {
			continue
		}
		if ok, _ := wan.Unclaimed(l, lans, configured); !ok {
			continue
		}
		if c, known := m.peek(l.Name); known && (c.State == wan.Added || c.State == wan.Probing) {
			continue
		}
		m.run(nil, "sysctl", "-qw", "net.ipv6.conf."+l.Name+".disable_ipv6=1")
		if _, err := m.run(nil, "ip", "link", "set", l.Name, "up"); err == nil {
			links[i].Up = true
		}
	}

	var toProbe *wan.Link
	m.update(func(f *wan.CandidatesFile) {
		present := map[string]bool{}
		for _, l := range links {
			present[l.Name] = true
			existing, known := f.Links[l.Name]
			if !known || existing.State != wan.Added {
				if ok, _ := wan.Unclaimed(l, lans, configured); !ok {
					if known && existing.State != wan.Probing {
						delete(f.Links, l.Name) // claimed since, by the LAN tab or by hand
					}
					continue
				}
			}
			var c *wan.Candidate
			if known {
				if existing.MAC != l.MAC {
					known = false // a different device under the same name
				} else {
					c = &existing
				}
			}
			switch wan.Decide(c, l, now) {
			case wan.RecordNoLink:
				f.Links[l.Name] = wan.Candidate{Interface: l.Name, MAC: l.MAC, State: wan.NoLink, CarrierChanges: l.CarrierChanges}
			case wan.Probe:
				if m.probing == "" && toProbe == nil {
					l := l
					toProbe = &l
					prev := f.Links[l.Name]
					prev.Interface, prev.MAC, prev.State, prev.Detail = l.Name, l.MAC, wan.Probing, ""
					f.Links[l.Name] = prev
				}
			}
		}
		for name, c := range f.Links {
			// An interface inside a probe's namespace is not visible here, and
			// an added link keeps its record for as long as its config exists.
			if !present[name] && c.State != wan.Probing && c.State != wan.Added {
				delete(f.Links, name)
			}
		}
		if toProbe != nil {
			m.probing = toProbe.Name
		}
	})
	if toProbe != nil {
		go m.probe(*toProbe)
	}
}

func (m *wanManager) probe(l wan.Link) {
	log.Printf("ompui: probing new link %s for DHCP and the internet", l.Name)
	out, err := m.run(nil, m.probeCmd, l.Name)
	r := wan.ParseProbe(string(out))
	if err != nil && r.Result == "error" && r.Detail == "" {
		r.Detail = err.Error()
	}
	// Read after the probe: moving the interface in and out of the namespace
	// counts as carrier changes of its own, which must not read as a replug.
	changes := readSys(l.Name, "carrier_changes")
	f := m.update(func(f *wan.CandidatesFile) {
		c := f.Links[l.Name]
		c.Interface, c.MAC = l.Name, l.MAC
		c.Apply(r, changes, time.Now().Unix())
		f.Links[l.Name] = c
		m.probing = ""
	})
	c := f.Links[l.Name]
	isp := ""
	if c.ISP != nil {
		isp = " (" + c.ISP.Name + ")"
	}
	log.Printf("ompui: new link %s%s: %s %s", l.Name, isp, c.State, c.Detail)
}

// ignore records the owner declining a link.
func (m *wanManager) ignore(iface string) error {
	var err error
	m.update(func(f *wan.CandidatesFile) {
		c, ok := f.Links[iface]
		if !ok || (c.State != wan.Ready && c.State != wan.AddFailed && c.State != wan.NoInternet) {
			err = fmt.Errorf("%s is not waiting for a decision", iface)
			return
		}
		c.State, c.Detail = wan.Ignored, "ignored from the web interface; replug it to check it again"
		f.Links[iface] = c
	})
	return err
}

// recheck probes a link again now, rather than at its next retry.
func (m *wanManager) recheck(iface string) error {
	var err error
	m.update(func(f *wan.CandidatesFile) {
		c, ok := f.Links[iface]
		if !ok {
			err = fmt.Errorf("no new link %s", iface)
			return
		}
		switch c.State {
		case wan.Probing, wan.Adding, wan.Added:
			err = fmt.Errorf("%s is %s", iface, c.State)
			return
		}
		c.RetryUnix, c.CarrierChanges = 0, -1 // reads as replugged
		if c.State == wan.Ready {
			c.State = wan.NoInternet
		}
		f.Links[iface] = c
	})
	if err == nil {
		go m.scan()
	}
	return err
}

// add provisions a ready link as a WAN link and restarts the daemon to take
// it on. Anything that fails before the restart is undone.
func (m *wanManager) add(iface string) error {
	var cand wan.Candidate
	var err error
	m.update(func(f *wan.CandidatesFile) {
		c, ok := f.Links[iface]
		if !ok || (c.State != wan.Ready && c.State != wan.AddFailed) {
			err = fmt.Errorf("%s is not ready to add", iface)
			return
		}
		c.State, c.Detail = wan.Adding, ""
		f.Links[iface] = c
		cand = c
	})
	if err != nil {
		return err
	}
	go func() {
		transport, err := m.provision(cand)
		m.update(func(f *wan.CandidatesFile) {
			c := f.Links[iface]
			if err != nil {
				c.State, c.Detail = wan.AddFailed, err.Error()
			} else {
				c.State, c.Detail, c.Transport = wan.Added, "added as "+transport, transport
			}
			f.Links[iface] = c
		})
		if err != nil {
			log.Printf("ompui: adding %s failed and was undone: %v", iface, err)
			return
		}
		log.Printf("ompui: %s added as %s; restarting %s to take it on as a path", iface, transport, m.daemonUnit)
		if out, err := m.run(nil, "systemctl", "restart", m.daemonUnit); err != nil {
			log.Printf("ompui: restarting %s: %v: %s", m.daemonUnit, err, out)
		}
	}()
	return nil
}

func (m *wanManager) provision(c wan.Candidate) (string, error) {
	confs, err := wan.ReadWGConfs(m.wgDir)
	if err != nil {
		return "", fmt.Errorf("reading WireGuard configs: %w", err)
	}
	plan, err := wan.PlanTransport(c.Interface, c.MAC, confs)
	if err != nil {
		return "", err
	}
	if c.ISP != nil {
		plan.ISP = c.ISP.Name
	}

	var written []string
	undo := func() {
		m.run(nil, "systemctl", "disable", "--now", "wg-quick@"+plan.Transport)
		for _, p := range written {
			os.Remove(p)
		}
		os.Remove(filepath.Dir(plan.DropinPath()))
		m.run(nil, "netplan", "generate")
		m.run(nil, "networkctl", "reload")
		reassertGuard(m.run)
	}
	write := func(path, content string, mode os.FileMode) error {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists; not overwriting it", path)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := lan.WriteAtomic(path, []byte(content), mode); err != nil {
			return err
		}
		written = append(written, path)
		return nil
	}

	key, err := m.run(nil, "wg", "genkey")
	if err != nil {
		return "", fmt.Errorf("wg genkey: %v", err)
	}
	priv := strings.TrimSpace(string(key))
	steps := []func() error{
		func() error { return write(plan.WGKeyPath(), priv+"\n", 0o600) },
		func() error { return write(plan.WGConfPath(), wan.RenderWGConf(plan, priv), 0o600) },
		func() error {
			return write(filepath.Join(m.netplanDir, filepath.Base(plan.NetplanPath())), wan.RenderNetplan(plan), 0o600)
		},
		func() error { return write(plan.DropinPath(), wan.RenderDropin(plan), 0o644) },
		func() error {
			if out, err := m.run(nil, "netplan", "generate"); err != nil {
				return fmt.Errorf("netplan generate: %s", strings.TrimSpace(string(out)))
			}
			return nil
		},
		func() error {
			m.run(nil, "networkctl", "reload")
			reassertGuard(m.run)
			if out, err := m.run(nil, "networkctl", "reconfigure", c.Interface); err != nil {
				return fmt.Errorf("networkctl reconfigure %s: %s", c.Interface, strings.TrimSpace(string(out)))
			}
			return nil
		},
		func() error {
			if out, err := m.run(nil, "systemctl", "enable", "--now", "wg-quick@"+plan.Transport); err != nil {
				return fmt.Errorf("starting %s: %s", plan.Transport, strings.TrimSpace(string(out)))
			}
			return nil
		},
	}
	for _, step := range steps {
		if err := step(); err != nil {
			undo()
			return "", err
		}
	}

	// Name the path at once from what the probe learned; the refresher
	// confirms it through the transport itself once the link is carrying it.
	if c.ISP != nil {
		m.saveISP(plan.Transport, *c.ISP)
	}
	return plan.Transport, nil
}

func (m *wanManager) saveISP(transport string, isp wan.ISP) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, err := wan.LoadISPs(m.ispPath)
	if err != nil {
		log.Printf("ompui: %v; replacing it", err)
	}
	if f.Links[transport].Name != isp.Name {
		log.Printf("ompui: %s is %s (%s, %s)", transport, isp.Name, isp.Org, isp.PublicIP)
	}
	f.Links[transport] = isp
	if err := wan.SaveISPs(m.ispPath, f); err != nil {
		log.Printf("ompui: saving ISP names: %v", err)
	}
}

// refreshISPs looks up the ISP of each transport whose path has just come up,
// or whose name is missing or old.
func (m *wanManager) refreshISPs() {
	snap, err := state.Read(m.statePath)
	if err != nil || snap.Age() > time.Minute {
		return
	}
	isps, _ := wan.LoadISPs(m.ispPath)
	for _, p := range snap.Paths {
		if p.Name == "" {
			continue
		}
		m.mu.Lock()
		cameUp := p.Alive && !m.lastAlive[p.Name]
		m.lastAlive[p.Name] = p.Alive
		recent := time.Since(m.lastISP[p.Name]) < ispMinGap
		m.mu.Unlock()
		if !p.Alive || recent {
			continue
		}
		have, ok := isps.Links[p.Name]
		stale := !ok || time.Since(time.Unix(have.CheckedUnix, 0)) > ispMaxAge
		if !cameUp && !stale {
			continue
		}
		markOut, err := m.run(nil, "wg", "show", p.Name, "fwmark")
		mark, perr := strconv.ParseUint(strings.TrimSpace(string(markOut)), 0, 32)
		if err != nil || perr != nil || mark == 0 {
			continue
		}
		m.mu.Lock()
		m.lastISP[p.Name] = time.Now()
		m.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		isp, err := lookupISP(ctx, m.ipinfoURL, uint32(mark))
		cancel()
		if err != nil {
			log.Printf("ompui: looking up %s's ISP: %v", p.Name, err)
			continue
		}
		m.saveISP(p.Name, isp)
	}
}

// lookupISP asks ipinfo.io who we are, from a socket carrying a transport's
// fwmark, so the connection leaves by that transport's own link. The name is
// resolved normally, through the tunnel; only the connection is pinned.
func lookupISP(ctx context.Context, url string, mark uint32) (wan.ISP, error) {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
			}); err != nil {
				return err
			}
			return serr
		},
	}
	client := &http.Client{Transport: &http.Transport{DialContext: dialer.DialContext, DisableKeepAlives: true}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return wan.ISP{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return wan.ISP{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return wan.ISP{}, fmt.Errorf("ipinfo.io answered %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return wan.ISP{}, err
	}
	return wan.ParseIPInfo(body, time.Now().Unix())
}

// handleWAN serves the new-link record and each link's ISP.
func (s *server) handleWAN(w http.ResponseWriter, r *http.Request) {
	if s.wan == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	m := s.wan
	m.mu.Lock()
	f, _ := wan.LoadCandidates(m.candPath)
	isps, _ := wan.LoadISPs(m.ispPath)
	probing := m.probing
	m.mu.Unlock()
	list := make([]wan.Candidate, 0, len(f.Links))
	for _, c := range f.Links {
		list = append(list, c)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Interface < list[j].Interface })
	writeJSON(w, http.StatusOK, map[string]any{
		"available":     true,
		"candidates":    list,
		"isps":          isps.Links,
		"probing":       probing,
		"retry_seconds": wan.RetrySeconds,
		"now_unix":      time.Now().Unix(),
	})
}

func (s *server) handleWANAction(action func(*wanManager, string) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || s.wan == nil {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Interface string `json:"interface"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Interface == "" {
			http.Error(w, "expected a JSON body with an interface", http.StatusBadRequest)
			return
		}
		if err := action(s.wan, req.Interface); err != nil {
			code := http.StatusConflict
			if errors.Is(err, os.ErrNotExist) {
				code = http.StatusNotFound
			}
			http.Error(w, err.Error(), code)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}

func hasDevice(iface string) bool {
	_, err := os.Stat(filepath.Join("/sys/class/net", iface, "device"))
	return err == nil
}
