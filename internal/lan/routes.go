package lan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// Home's side of D-068: routing the vehicle's LAN subnets back down the
// tunnel, and translating them onto home's network where NAT is enabled.
//
// Home cannot work these out for itself - the LAN lives on the vehicle - so
// the vehicle tells it over the wire whenever they change. Everything here
// runs on home, and everything here is guarded, because a subnet arriving off
// the network is being written into home's routing table: a vehicle that
// claimed home's own LAN would take home off its own network.

// DefaultRoutesPath is where home keeps the last set it was given, so the
// routes come back with the daemon after a restart or a reboot without
// waiting for the vehicle to be reachable again.
const DefaultRoutesPath = "/var/lib/openmultipath/lan-routes.json"

// NAT set: home's nftables.conf names this set in its masquerade rule, and
// the daemon keeps its elements in step with the vehicle's LANs. D-013 has
// NAT off by default; with no such set there is nothing to keep in step,
// and that is not an error.
const (
	NATTable = "inet omp-nat"
	NATSet   = "vehicle_lans"
)

// RouteDecision is what home did with one subnet the vehicle named.
type RouteDecision struct {
	Prefix    netip.Prefix
	Installed bool
	Reason    string
}

// Screen decides which of the vehicle's subnets home may route, given the
// networks home is itself attached to. A pure function, so the guard can be
// tested without a routing table to damage.
func Screen(want []netip.Prefix, local []netip.Prefix) []RouteDecision {
	out := make([]RouteDecision, 0, len(want))
	for _, p := range want {
		p = p.Masked()
		d := RouteDecision{Prefix: p}
		switch {
		case !p.Addr().Is4():
			d.Reason = "not IPv4"
		case p.Bits() < 16:
			d.Reason = fmt.Sprintf("a /%d is wider than any LAN", p.Bits())
		case !p.Addr().IsPrivate():
			d.Reason = "not a private range"
		default:
			for _, r := range Reserved {
				if r.Overlaps(p) {
					d.Reason = fmt.Sprintf("overlaps the tunnel's own %s", r)
				}
			}
			for _, l := range local {
				if d.Reason == "" && l.Overlaps(p) {
					d.Reason = fmt.Sprintf("overlaps %s, which is attached to home itself", l.Masked())
				}
			}
		}
		d.Installed = d.Reason == ""
		out = append(out, d)
	}
	return out
}

// LocalPrefixes lists the IPv4 networks on home's interfaces, other than the
// tunnel device the vehicle's routes point into.
func LocalPrefixes(tun string) []netip.Prefix {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, i := range ifaces {
		if i.Name == tun || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(n.IP)
			if !ok || !ip.Unmap().Is4() {
				continue
			}
			bits, _ := n.Mask.Size()
			out = append(out, netip.PrefixFrom(ip.Unmap(), bits).Masked())
		}
	}
	return out
}

// HomeRoutes applies the vehicle's subnets to home.
type HomeRoutes struct {
	Tun  string
	Path string // where the set is kept; empty keeps nothing

	held []netip.Prefix // what was last installed, to know what to remove
}

// routesFile is the persisted set.
type routesFile struct {
	Subnets []string `json:"subnets"`
}

// LoadHeld reads the set kept from last time. A missing file is an empty set.
func (h *HomeRoutes) LoadHeld() []netip.Prefix {
	if h.Path == "" {
		return nil
	}
	b, err := os.ReadFile(h.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		log.Printf("lan routes: %v", err)
		return nil
	}
	var f routesFile
	if err := json.Unmarshal(b, &f); err != nil {
		log.Printf("lan routes: %s: %v", h.Path, err)
		return nil
	}
	var out []netip.Prefix
	for _, s := range f.Subnets {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// Apply installs routes for every subnet the guard allows, removes the ones
// home installed for a previous set that are no longer wanted, brings the
// NAT set into step, and keeps the set for the next start.
//
// A command that fails is logged and the rest carry on. Half the LANs
// routed is better than none, and the vehicle retries nothing on its own:
// the next change, or the next daemon start, applies the whole set again.
func (h *HomeRoutes) Apply(want []netip.Prefix) []RouteDecision {
	decisions := Screen(want, LocalPrefixes(h.Tun))
	keep := map[netip.Prefix]bool{}
	var installed []netip.Prefix
	for _, d := range decisions {
		if !d.Installed {
			log.Printf("lan routes: not routing %s: %s", d.Prefix, d.Reason)
			continue
		}
		if out, err := exec.Command("ip", "route", "replace", d.Prefix.String(), "dev", h.Tun).CombinedOutput(); err != nil {
			log.Printf("lan routes: route %s via %s: %v: %s", d.Prefix, h.Tun, err, strings.TrimSpace(string(out)))
		}
		keep[d.Prefix] = true
		installed = append(installed, d.Prefix)
	}
	for _, old := range h.held {
		if keep[old] {
			continue
		}
		// Only a route that still points at the tunnel: if something else
		// has taken the prefix over since, it is not ours to delete.
		if err := exec.Command("ip", "route", "del", old.String(), "dev", h.Tun).Run(); err == nil {
			log.Printf("lan routes: removed %s, no longer a vehicle LAN", old)
		}
	}
	h.held = installed
	h.syncNAT(installed)
	h.save(installed)
	return decisions
}

// Restore puts back the set kept from last time, for use at startup, once
// the tunnel device exists.
func (h *HomeRoutes) Restore() []RouteDecision {
	held := h.LoadHeld()
	if len(held) == 0 {
		return nil
	}
	log.Printf("lan routes: restoring %s from %s", prefixList(held), h.Path)
	// Seed what is held first, so a subnet the guard now refuses - home's
	// own network has moved onto it since - is still removed from the tunnel.
	h.held = held
	return h.Apply(held)
}

// syncNAT replaces the NAT set's elements in one nft transaction, so there
// is never a moment where a LAN that was translated is not.
func (h *HomeRoutes) syncNAT(set []netip.Prefix) {
	if exec.Command("nft", "list", "set", NATTable, NATSet).Run() != nil {
		return // NAT is not enabled on this home (D-013's default)
	}
	script := fmt.Sprintf("flush set %s %s\n", NATTable, NATSet)
	if len(set) > 0 {
		script += fmt.Sprintf("add element %s %s { %s }\n", NATTable, NATSet, prefixList(set))
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("lan routes: updating NAT set: %v: %s", err, strings.TrimSpace(string(out)))
	}
}

func (h *HomeRoutes) save(set []netip.Prefix) {
	if h.Path == "" {
		return
	}
	f := routesFile{Subnets: []string{}}
	for _, p := range set {
		f.Subnets = append(f.Subnets, p.String())
	}
	sort.Strings(f.Subnets)
	b, _ := json.MarshalIndent(f, "", "  ")
	if err := WriteAtomic(h.Path, append(b, '\n'), 0o644); err != nil {
		log.Printf("lan routes: saving %s: %v", h.Path, err)
	}
}

func prefixList(set []netip.Prefix) string {
	s := make([]string, len(set))
	for i, p := range set {
		s[i] = p.String()
	}
	return strings.Join(s, ", ")
}
