// Package linkdisco decides which of the vehicle's network interfaces are
// WAN uplinks worth building a tunnel over, so the RV does not have to be
// told its own links by name.
//
// scope-v1.md's install design asks for exactly this: "Enumerate interfaces
// at startup and classify by type ... The user confirms a list; they do not
// name interfaces." This is the enumeration half. It is deliberately blunt:
// a WAN uplink here is any interface that is up, carries a routable IPv4
// address, and is neither the LAN side nor something virtual. Type-aware
// classification - ModemManager for cellular, the dish's address for
// Starlink - is a refinement on top of a working list, not a prerequisite
// for one.
//
// The choice is a pure function of a description of the interfaces so it can
// be tested without the machine actually having the links, which is the only
// way to test "picks both modems, ignores the LAN and the tunnel" on a
// bench. Discover is the thin shell that reads the real interfaces and hands
// them to it.
package linkdisco

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// Iface is the slice of an interface the selection reasons about.
type Iface struct {
	Name         string
	Up           bool
	Loopback     bool
	PointToPoint bool
	Addrs        []net.IPNet
}

// virtualPrefixes name interfaces that are never a WAN uplink: tunnels the
// daemon or wg-quick built, bridges, container veths, dial-up and tunnelling
// pseudo-devices. Matching by name is crude, but the name is what an
// operator reads in `ip link` and reasons about at 2am, so a rule stated in
// those terms is the one that can be checked by eye.
var virtualPrefixes = []string{
	"lo", "wg", "omp", "tun", "tap", "docker", "br", "veth",
	"virbr", "tailscale", "ppp", "dummy", "gre", "sit",
}

func isVirtual(name string) bool {
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// Classify decides whether one interface is a WAN uplink, returning a reason
// either way so the daemon can log what it saw and a human can see why a link
// they expected was left out.
//
// The order of the checks is the order of the explanations: the first thing
// that disqualifies an interface is the thing worth saying about it.
func Classify(i Iface, lan *net.IPNet, wg string) (ok bool, reason string) {
	switch {
	case i.Loopback:
		return false, "loopback"
	case i.Name == wg:
		return false, "the tunnel interface itself"
	case isVirtual(i.Name):
		return false, "virtual or tunnel interface"
	}

	ip, hasV4 := firstGlobalV4(i.Addrs)
	if !hasV4 {
		if !i.Up {
			return false, "down and unaddressed"
		}
		return false, "no routable IPv4 address"
	}
	if lan != nil && lan.Contains(ip) {
		// The RV's own LAN side, and the out-of-band Wi-Fi lifeline, both
		// live in this subnet. Neither is a way out to home, and pinning a
		// path to the lifeline would put project traffic on the one link
		// that has to stay clear for recovery.
		return false, fmt.Sprintf("address %s is on the LAN %s, not a WAN uplink", ip, lan)
	}
	if !i.Up {
		// Addressed but administratively down. Naming it would create a
		// path that is down from birth; better to leave it out and let an
		// operator add it by name if they mean to use it.
		return false, fmt.Sprintf("has %s but is administratively down", ip)
	}
	return true, fmt.Sprintf("WAN uplink at %s", ip)
}

// Select returns the chosen uplink names in a stable order, with the reason
// each interface was included or excluded.
//
// The order is by name and not by discovery order, because a path's id is
// its index in this list and that id carries the path's whole measurement
// history across restarts. A stable order means a link keeps its identity
// from one boot to the next; sorting by whatever order the kernel happened
// to enumerate would shuffle histories between links.
func Select(ifaces []Iface, lan *net.IPNet, wg string) (picked []string, reasons map[string]string) {
	reasons = make(map[string]string, len(ifaces))
	for _, i := range ifaces {
		ok, why := Classify(i, lan, wg)
		reasons[i.Name] = why
		if ok {
			picked = append(picked, i.Name)
		}
	}
	sort.Strings(picked)
	return picked, reasons
}

// SelectTransports picks the WireGuard transport interfaces the daemon rides
// when it runs above WireGuard (D-020), where its paths are not the physical
// NICs at all.
//
// Above WireGuard the daemon writes plaintext into a TUN and sends over the
// wg interfaces, each of which is a tunnel to home pinned to one physical NIC
// by fwmark a layer below. So the thing to detect here is the set of wg
// transports - point-to-point interfaces whose name marks them WireGuard -
// and pointing the daemon at the NICs instead would be sending its packets to
// home's inner address over a link that cannot reach it. own is the daemon's
// own tun / -wg-interface, excluded so it does not try to ride over itself.
func SelectTransports(ifaces []Iface, own string) (picked []string, reasons map[string]string) {
	reasons = make(map[string]string, len(ifaces))
	for _, i := range ifaces {
		ok, why := classifyTransport(i, own)
		reasons[i.Name] = why
		if ok {
			picked = append(picked, i.Name)
		}
	}
	sort.Strings(picked)
	return picked, reasons
}

func classifyTransport(i Iface, own string) (ok bool, reason string) {
	switch {
	case i.Name == own:
		return false, "the daemon's own tunnel device"
	case !strings.HasPrefix(i.Name, "wg"):
		return false, "not a WireGuard transport"
	case !i.PointToPoint:
		return false, "not point-to-point"
	case !i.Up:
		return false, "down"
	}
	return true, "WireGuard transport tunnel"
}

// readInterfaces gathers the machine's real interfaces into the description
// the selectors work on.
func readInterfaces() ([]Iface, error) {
	sys, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("linkdisco: read interfaces: %w", err)
	}
	ifaces := make([]Iface, 0, len(sys))
	for _, s := range sys {
		addrs, _ := s.Addrs()
		nets := make([]net.IPNet, 0, len(addrs))
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				nets = append(nets, *n)
			}
		}
		ifaces = append(ifaces, Iface{
			Name:         s.Name,
			Up:           s.Flags&net.FlagUp != 0,
			Loopback:     s.Flags&net.FlagLoopback != 0,
			PointToPoint: s.Flags&net.FlagPointToPoint != 0,
			Addrs:        nets,
		})
	}
	return ifaces, nil
}

// Discover reads the machine's interfaces and selects the WAN uplinks among
// them. lan is the subnet home routes to the vehicle - the RV's own LAN -
// whose interfaces are never uplinks; pass nil to skip that exclusion. wg is
// the tunnel interface's name, excluded so a re-run after the tunnel is up
// does not try to build a path over the tunnel.
func Discover(lan *net.IPNet, wg string) (picked []string, reasons map[string]string, err error) {
	ifaces, err := readInterfaces()
	if err != nil {
		return nil, nil, err
	}
	picked, reasons = Select(ifaces, lan, wg)
	return picked, reasons, nil
}

// DiscoverTransports reads the machine's interfaces and selects the
// WireGuard transports (see SelectTransports), for a daemon running above
// WireGuard. own is the daemon's own tun / -wg-interface.
func DiscoverTransports(own string) (picked []string, reasons map[string]string, err error) {
	ifaces, err := readInterfaces()
	if err != nil {
		return nil, nil, err
	}
	picked, reasons = SelectTransports(ifaces, own)
	return picked, reasons, nil
}

// firstGlobalV4 returns an interface's first routable IPv4 address. It
// mirrors the relay's own pickIPv4: IPv4 only (the sockets and the home
// endpoint are v4), and link-local skipped because a cellular interface
// carries a 169.254 address in the gap between the link coming up and DHCP
// completing, which is not an address anything can be reached on.
func firstGlobalV4(addrs []net.IPNet) (net.IP, bool) {
	for _, n := range addrs {
		ip := n.IP.To4()
		if ip == nil || !ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() {
			continue
		}
		return ip, true
	}
	return nil, false
}
