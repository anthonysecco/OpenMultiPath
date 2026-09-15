package main

// The LAN tab (D-067): the vehicle's LAN segments, their DHCP service, and
// the devices on them.
//
// ompui does no networking itself. It keeps internal/lan's settings file and
// renders it into the files netplan and dnsmasq already read, then asks those
// tools to pick the change up. The dangerous part is an address change: it
// can cut off the very browser that made it. So a change to addressing goes
// on probation, like a new ompd does in omp-deploy - it stays only if it is
// confirmed from the new address within the window, and is put back by
// itself otherwise. The deadline is on disk, so an ompui restart or a reboot
// in the middle of it still ends in a network somebody can reach.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/lan"
	"github.com/anthonysecco/OpenMultiPath/internal/state"
)

// lanProbationSeconds is how long an address change has to be confirmed.
// Long enough to rejoin a Wi-Fi network and reload the page at the new
// address; short enough that a mistake is undone before anyone drives
// anywhere to fix it.
const lanProbationSeconds = 120

// lanManager owns the LAN settings and everything rendered from them.
type lanManager struct {
	path        string // lan.json
	netplanPath string
	dnsmasqPath string
	envPath     string
	leasePath   string
	netplanDir  string
	stateDir    string // probation marker and backups

	// run executes a command; replaced in tests.
	run func(env []string, name string, args ...string) ([]byte, error)

	mu        sync.Mutex
	deadline  time.Time   // zero when nothing is on probation
	timer     *time.Timer // fires the revert
	previous  *lan.File   // the settings a revert goes back to
	lastError string      // the last apply or revert failure, for the page
}

func newLANManager(path, stateDir string) *lanManager {
	return &lanManager{
		path:        path,
		netplanPath: lan.NetplanPath,
		dnsmasqPath: lan.DnsmasqPath,
		envPath:     lan.EnvPath,
		leasePath:   lan.LeasePath,
		netplanDir:  filepath.Dir(lan.NetplanPath),
		stateDir:    stateDir,
		run: func(env []string, name string, args ...string) ([]byte, error) {
			cmd := exec.Command(name, args...)
			cmd.Env = append(os.Environ(), env...)
			return cmd.CombinedOutput()
		},
	}
}

func (m *lanManager) markerPath() string { return filepath.Join(m.stateDir, "lan-probation.json") }
func (m *lanManager) backupPath() string { return filepath.Join(m.stateDir, "lan-previous.json") }

// backup is every file an apply rewrites, as it was before. A nil entry is a
// file that did not exist, which a revert removes.
type backup struct {
	Settings *lan.File          `json:"settings"` // nil when the LAN was not configured
	Files    map[string]*string `json:"files"`
}

type probationMarker struct {
	DeadlineUnix int64 `json:"deadline_unix"`
}

// resume picks up a probation left running by a previous ompui, reverting at
// once if its deadline has already passed. Called at startup.
func (m *lanManager) resume() {
	b, err := os.ReadFile(m.markerPath())
	if err != nil {
		return
	}
	var mk probationMarker
	if json.Unmarshal(b, &mk) != nil {
		mk.DeadlineUnix = 0
	}
	bk, err := m.loadBackup()
	if err != nil {
		log.Printf("ompui: LAN probation marker found but its backup is unreadable (%v); keeping the current LAN", err)
		os.Remove(m.markerPath())
		return
	}
	left := time.Until(time.Unix(mk.DeadlineUnix, 0))
	if left <= 0 {
		log.Printf("ompui: an unconfirmed LAN change outlived its probation; putting the previous LAN back")
		m.mu.Lock()
		defer m.mu.Unlock()
		m.previous = bk.Settings
		if err := m.revertLocked(bk); err != nil {
			m.lastError = err.Error()
		}
		return
	}
	log.Printf("ompui: resuming LAN probation, %s left", left.Round(time.Second))
	m.mu.Lock()
	defer m.mu.Unlock()
	m.previous = bk.Settings
	m.startTimerLocked(time.Unix(mk.DeadlineUnix, 0))
}

func (m *lanManager) loadBackup() (backup, error) {
	var bk backup
	b, err := os.ReadFile(m.backupPath())
	if err != nil {
		return bk, err
	}
	err = json.Unmarshal(b, &bk)
	return bk, err
}

func (m *lanManager) startTimerLocked(deadline time.Time) {
	m.deadline = deadline
	if m.timer != nil {
		m.timer.Stop()
	}
	m.timer = time.AfterFunc(time.Until(deadline), func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.deadline.IsZero() || time.Now().Before(m.deadline) {
			return
		}
		log.Printf("ompui: LAN change not confirmed in %ds; putting the previous LAN back", lanProbationSeconds)
		bk, err := m.loadBackup()
		if err != nil {
			m.lastError = "could not read the previous LAN to revert to: " + err.Error()
			m.clearProbationLocked()
			return
		}
		if err := m.revertLocked(bk); err != nil {
			m.lastError = err.Error()
		} else {
			m.lastError = "The address change was not confirmed in time and was undone."
		}
	})
}

func (m *lanManager) clearProbationLocked() {
	m.deadline = time.Time{}
	m.previous = nil
	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}
	os.Remove(m.markerPath())
}

// current returns the saved settings, or nil when the LAN is not managed.
func (m *lanManager) current() (*lan.File, error) {
	f, err := lan.Load(m.path)
	if errors.Is(err, lan.ErrNotConfigured) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// conflicts finds other netplan files that also configure an interface this
// one is about to. netplan merges them, and two address lists for one
// interface merge into both addresses at once, which is not a change anyone
// asked for.
func (m *lanManager) conflicts(f lan.File) []string {
	files, _ := filepath.Glob(filepath.Join(m.netplanDir, "*.yaml"))
	var out []string
	for _, file := range files {
		if file == m.netplanPath {
			continue
		}
		b, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		for _, s := range f.Segments {
			re := regexp.MustCompile(`(?m)^\s+` + regexp.QuoteMeta(s.Interface) + `:\s*$`)
			if re.Match(b) {
				out = append(out, fmt.Sprintf("%s is already configured in %s. Remove it there first so this LAN is its only configuration.", s.Interface, file))
			}
		}
	}
	return out
}

// apply saves and applies new settings. An error means nothing was changed:
// the files are put back as they were.
func (m *lanManager) apply(next lan.File) (probation bool, err error) {
	next = next.WithDefaults()
	if errs := next.Validate(); len(errs) > 0 {
		return false, validationError(errs)
	}
	if errs := m.conflicts(next); len(errs) > 0 {
		return false, validationError(errs)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	prev, err := m.current()
	if err != nil {
		return false, fmt.Errorf("reading the current LAN settings: %w", err)
	}

	// What is there now, to put back if this apply fails part way. A change
	// made during probation keeps the backup saved when probation began, so
	// a revert goes back to the last network somebody confirmed rather than
	// to an intermediate one nobody could reach.
	onProbation := !m.deadline.IsZero()
	bk := m.snapshot(prev)

	if err := m.write(next); err != nil {
		m.restoreFiles(bk.Files)
		return false, err
	}
	if out, err := m.run(nil, "netplan", "generate"); err != nil {
		m.restoreFiles(bk.Files)
		m.run(nil, "netplan", "generate")
		return false, fmt.Errorf("netplan rejected the configuration: %s", strings.TrimSpace(string(out)))
	}
	m.activate(prev, &next)

	needProbation := prev != nil && !lan.AddressingEqual(*prev, next)
	if onProbation {
		// Still on probation from the first change; the clock keeps running.
		return true, nil
	}
	if !needProbation {
		return false, nil
	}
	if err := m.saveBackup(bk); err != nil {
		// No backup means no safe revert: undo the change now rather than
		// leave an unconfirmable one in place.
		m.restoreFiles(bk.Files)
		m.run(nil, "netplan", "generate")
		m.activate(&next, prev)
		return false, fmt.Errorf("could not save the previous LAN for probation: %w", err)
	}
	deadline := time.Now().Add(lanProbationSeconds * time.Second)
	mk, _ := json.Marshal(probationMarker{DeadlineUnix: deadline.Unix()})
	if err := lan.WriteAtomic(m.markerPath(), mk, 0o644); err != nil {
		log.Printf("ompui: writing the LAN probation marker: %v", err)
	}
	m.previous = prev
	m.lastError = ""
	m.startTimerLocked(deadline)
	return true, nil
}

// confirm keeps a change on probation.
func (m *lanManager) confirm() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deadline.IsZero() {
		return false
	}
	m.clearProbationLocked()
	os.Remove(m.backupPath())
	m.lastError = ""
	log.Printf("ompui: LAN change confirmed")
	return true
}

// revertNow undoes a change on probation straight away.
func (m *lanManager) revertNow() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deadline.IsZero() {
		return errors.New("nothing to revert")
	}
	bk, err := m.loadBackup()
	if err != nil {
		return err
	}
	return m.revertLocked(bk)
}

func (m *lanManager) revertLocked(bk backup) error {
	now, _ := m.current()
	m.restoreFiles(bk.Files)
	_, genErr := m.run(nil, "netplan", "generate")
	m.activate(now, bk.Settings)
	m.clearProbationLocked()
	os.Remove(m.backupPath())
	if genErr != nil {
		return fmt.Errorf("the previous netplan did not generate either: %v", genErr)
	}
	log.Printf("ompui: previous LAN restored")
	return nil
}

func (m *lanManager) managedFiles() []string {
	return []string{m.path, m.netplanPath, m.dnsmasqPath, m.envPath}
}

func (m *lanManager) snapshot(prev *lan.File) backup {
	bk := backup{Settings: prev, Files: map[string]*string{}}
	for _, p := range m.managedFiles() {
		if b, err := os.ReadFile(p); err == nil {
			s := string(b)
			bk.Files[p] = &s
		} else {
			bk.Files[p] = nil
		}
	}
	return bk
}

func (m *lanManager) saveBackup(bk backup) error {
	b, err := json.Marshal(bk)
	if err != nil {
		return err
	}
	return lan.WriteAtomic(m.backupPath(), b, 0o600)
}

func (m *lanManager) restoreFiles(files map[string]*string) {
	for p, content := range files {
		if content == nil {
			os.Remove(p)
			continue
		}
		mode := os.FileMode(0o644)
		if p == m.netplanPath {
			mode = 0o600
		}
		if err := lan.WriteAtomic(p, []byte(*content), mode); err != nil {
			log.Printf("ompui: restoring %s: %v", p, err)
		}
	}
}

// write renders every managed file. The dnsmasq file is checked by dnsmasq
// itself before it replaces the running one.
func (m *lanManager) write(f lan.File) error {
	conf := lan.RenderDnsmasq(f)
	if dnsmasqInstalled() {
		tmp, err := os.CreateTemp(m.stateDir, "dnsmasq-check-*.conf")
		if err == nil {
			tmp.WriteString(conf)
			tmp.Close()
			out, err := m.run(nil, "dnsmasq", "--test", "--conf-file="+tmp.Name())
			os.Remove(tmp.Name())
			if err != nil {
				return fmt.Errorf("dnsmasq rejected the DHCP configuration: %s", strings.TrimSpace(string(out)))
			}
		}
	}
	// netplan refuses to read a world-readable file without a warning.
	if err := lan.WriteAtomic(m.netplanPath, []byte(lan.RenderNetplan(f)), 0o600); err != nil {
		return err
	}
	if err := lan.WriteAtomic(m.dnsmasqPath, []byte(conf), 0o644); err != nil {
		return err
	}
	if err := lan.WriteAtomic(m.envPath, []byte(lan.LANEnv(f)), 0o644); err != nil {
		return err
	}
	return lan.Save(m.path, f)
}

// activate makes the running system match what was just written: networkd
// for addresses, dnsmasq for DHCP and DNS, and the PEP's interception rules
// for the subnets they match on. Each step's failure is logged and the rest
// still run; a DHCP server that will not restart is no reason to leave a new
// address half applied.
func (m *lanManager) activate(from, to *lan.File) {
	if out, err := m.run(nil, "networkctl", "reload"); err != nil {
		log.Printf("ompui: networkctl reload: %v: %s", err, strings.TrimSpace(string(out)))
	}
	// Only the interfaces whose addressing changed. Reconfiguring a link
	// re-applies its addresses, and a LAN whose settings did not change has
	// devices on it that should not see it blink because a lease time on
	// another LAN was edited.
	for _, n := range changedInterfaces(from, to) {
		if _, err := net.InterfaceByName(n); err != nil {
			continue
		}
		if out, err := m.run(nil, "networkctl", "reconfigure", n); err != nil {
			log.Printf("ompui: networkctl reconfigure %s: %v: %s", n, err, strings.TrimSpace(string(out)))
		}
	}

	if dnsmasqInstalled() {
		m.run(nil, "systemctl", "enable", "dnsmasq")
		if out, err := m.run(nil, "systemctl", "restart", "dnsmasq"); err != nil {
			log.Printf("ompui: restarting dnsmasq: %v: %s", err, strings.TrimSpace(string(out)))
		}
	}

	// Interception only follows the subnets if it is on in the first place.
	if _, err := m.run(nil, "systemctl", "is-active", "--quiet", "omp-pep-rules"); err == nil {
		if from != nil {
			m.run([]string{"OMP_LAN=" + subnetList(*from)}, "omp-pep-rules", "off")
		}
		if to != nil {
			if out, err := m.run([]string{"OMP_LAN=" + subnetList(*to)}, "omp-pep-rules", "on"); err != nil {
				log.Printf("ompui: omp-pep-rules on: %v: %s", err, strings.TrimSpace(string(out)))
			}
		}
	}
}

// changedInterfaces lists the interfaces added, removed, or given a new
// address or MAC between two settings, in name order.
func changedInterfaces(from, to *lan.File) []string {
	key := func(f *lan.File) map[string]string {
		out := map[string]string{}
		if f != nil {
			for _, s := range f.Segments {
				out[s.Interface] = s.Address + "@" + s.MAC
			}
		}
		return out
	}
	a, b := key(from), key(to)
	var names []string
	for n, v := range a {
		if b[n] != v {
			names = append(names, n)
		}
	}
	for n := range b {
		if _, ok := a[n]; !ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}

func subnetList(f lan.File) string {
	var s []string
	for _, p := range f.Subnets() {
		s = append(s, p.String())
	}
	return strings.Join(s, " ")
}

func dnsmasqInstalled() bool {
	_, err := exec.LookPath("dnsmasq")
	return err == nil
}

type validationError []string

func (v validationError) Error() string { return strings.Join(v, " ") }

// allowedLocal says whether a request that arrived at a local address may be
// served: the loopback, or an address on one of the LANs - including the
// ones a change on probation is moving away from, or the person confirming
// it from the old side could not. With no usable settings everything is
// allowed, because an unreachable management page is the worse failure.
func (m *lanManager) allowedLocal(local netip.Addr) bool {
	local = local.Unmap()
	if local.IsLoopback() {
		return true
	}
	cur, err := m.current()
	if err != nil || cur == nil {
		return true
	}
	m.mu.Lock()
	prev := m.previous
	m.mu.Unlock()
	for _, f := range []*lan.File{cur, prev} {
		if f == nil {
			continue
		}
		for _, p := range f.Subnets() {
			if p.Contains(local) {
				return true
			}
		}
	}
	return false
}

// lanGuard refuses requests that reached the interface on a non-LAN address.
func (s *server) lanGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
			if ap, err := netip.ParseAddrPort(a.String()); err == nil && !s.lan.allowedLocal(ap.Addr()) {
				http.Error(w, "the management interface is only served on the LAN", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// liveIface is one network interface as the LAN tab shows it.
type liveIface struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac"`
	Up        bool     `json:"up"`
	Carrier   bool     `json:"carrier"`
	Addresses []string `json:"addresses"`
	RxBytes   uint64   `json:"rx_bytes"`
	TxBytes   uint64   `json:"tx_bytes"`
	// Role is "lan" for a configured segment, "wan" for a link carrying a
	// default route, "unmanaged" for one configured in another netplan file
	// with no default route - a LAN set up by hand or by cloud-init, or a WAN
	// link that is down - and "unassigned" for one nothing has claimed.
	Role   string `json:"role"`
	Reason string `json:"reason,omitempty"`
}

var virtualPrefixes = []string{"lo", "wg", "omp", "tun", "tap", "docker", "br-", "veth", "virbr", "tailscale", "ppp", "dummy", "gre", "sit"}

func liveInterfaces(m *lanManager, f *lan.File) []liveIface {
	sys, err := net.Interfaces()
	if err != nil {
		return nil
	}
	defaults := defaultRouteDevs(m)
	elsewhere := map[string]string{}
	if files, _ := filepath.Glob(filepath.Join(m.netplanDir, "*.yaml")); files != nil {
		for _, file := range files {
			if file == m.netplanPath {
				continue
			}
			b, _ := os.ReadFile(file)
			for _, i := range sys {
				re := regexp.MustCompile(`(?m)^\s+` + regexp.QuoteMeta(i.Name) + `:\s*$`)
				if re.Match(b) {
					elsewhere[i.Name] = file
				}
			}
		}
	}

	var out []liveIface
	for _, i := range sys {
		virtual := false
		for _, p := range virtualPrefixes {
			if strings.HasPrefix(i.Name, p) {
				virtual = true
			}
		}
		if virtual {
			continue
		}
		li := liveIface{
			Name:    i.Name,
			MAC:     i.HardwareAddr.String(),
			Up:      i.Flags&net.FlagUp != 0,
			Carrier: readSys(i.Name, "carrier") == 1,
			RxBytes: uint64(readSys(i.Name, "statistics/rx_bytes")),
			TxBytes: uint64(readSys(i.Name, "statistics/tx_bytes")),
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
				li.Addresses = append(li.Addresses, n.String())
			}
		}
		switch {
		case f != nil && hasSegment(*f, i.Name):
			li.Role = "lan"
		case defaults[i.Name]:
			li.Role, li.Reason = "wan", "carries a default route"
		case elsewhere[i.Name] != "":
			li.Role, li.Reason = "unmanaged", "configured in "+elsewhere[i.Name]
		default:
			li.Role = "unassigned"
		}
		out = append(out, li)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out
}

func hasSegment(f lan.File, iface string) bool {
	_, ok := f.Segment(iface)
	return ok
}

func readSys(iface, name string) int64 {
	b, err := os.ReadFile(filepath.Join("/sys/class/net", iface, name))
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n
}

func defaultRouteDevs(m *lanManager) map[string]bool {
	out := map[string]bool{}
	b, err := m.run(nil, "ip", "-j", "route", "show", "table", "all", "default")
	if err != nil {
		return out
	}
	var routes []struct {
		Dev string `json:"dev"`
	}
	json.Unmarshal(b, &routes)
	for _, r := range routes {
		out[r.Dev] = true
	}
	return out
}

// proposal builds settings from the interfaces as they are, for a LAN that
// has never been saved: every interface with an address and no default route
// becomes a segment at that address, with DHCP off. Nothing is written until
// somebody saves it - and a save refuses to proceed while another netplan
// file still configures one of them, saying which.
func proposal(ifaces []liveIface) lan.File {
	f := lan.File{}
	n := 0
	for _, i := range ifaces {
		if (i.Role != "unassigned" && i.Role != "unmanaged") || len(i.Addresses) == 0 {
			continue
		}
		n++
		f.Segments = append(f.Segments, lan.Segment{
			Interface: i.Name,
			Name:      fmt.Sprintf("LAN %d", n),
			MAC:       i.MAC,
			Address:   i.Addresses[0],
		})
	}
	return f.WithDefaults()
}

func (s *server) handleLAN(w http.ResponseWriter, r *http.Request) {
	if s.lan == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.lanStatus(w)
	case http.MethodPost:
		var f lan.File
		if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
			http.Error(w, "could not read the submitted LAN settings: "+err.Error(), http.StatusBadRequest)
			return
		}
		probation, err := s.lan.apply(f)
		var verr validationError
		switch {
		case errors.As(err, &verr):
			writeJSON(w, http.StatusBadRequest, map[string]any{"errors": []string(verr)})
		case err != nil:
			writeJSON(w, http.StatusInternalServerError, map[string]any{"errors": []string{err.Error()}})
		default:
			writeJSON(w, http.StatusOK, map[string]any{"applied": true, "probation": probation, "probation_seconds": lanProbationSeconds})
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) lanStatus(w http.ResponseWriter) {
	m := s.lan
	cur, loadErr := m.current()
	ifaces := liveInterfaces(m, cur)

	out := map[string]any{"available": true, "probation_seconds_total": lanProbationSeconds}
	settings := cur
	if loadErr != nil {
		out["error"] = loadErr.Error()
	}
	if cur == nil {
		p := proposal(ifaces)
		settings = &p
	}
	out["configured"] = cur != nil
	out["settings"] = settings
	out["interfaces"] = ifaces

	leases := []lan.Lease{}
	if b, err := os.ReadFile(m.leasePath); err == nil {
		leases = lan.ParseLeases(string(b))
	}
	var neigh []lan.Neighbor
	if b, err := m.run(nil, "ip", "-j", "-4", "neigh", "show"); err == nil {
		neigh = lan.ParseNeighbors(b)
	}
	out["clients"] = lan.Clients(*settings, leases, neigh, time.Now().Unix())

	dns := map[string]any{"installed": dnsmasqInstalled()}
	if _, err := m.run(nil, "systemctl", "is-active", "--quiet", "dnsmasq"); err == nil {
		dns["active"] = true
	} else {
		dns["active"] = false
	}
	out["dnsmasq"] = dns

	m.mu.Lock()
	if !m.deadline.IsZero() {
		out["probation"] = map[string]any{"seconds_left": max(0, int(time.Until(m.deadline).Seconds()))}
	}
	if m.lastError != "" {
		out["notice"] = m.lastError
	}
	m.mu.Unlock()

	if snap, err := state.Read(s.statePath); err == nil {
		out["home_routes"] = snap.LANRoutes
		out["home_routes_age_seconds"] = snap.Age().Seconds()
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) handleLANConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || s.lan == nil {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"confirmed": s.lan.confirm()})
}

func (s *server) handleLANRevert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || s.lan == nil {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.lan.revertNow(); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reverted": true})
}
