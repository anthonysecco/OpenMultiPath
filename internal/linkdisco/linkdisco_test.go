package linkdisco

import (
	"net"
	"reflect"
	"testing"
)

func cidr(t *testing.T, s string) net.IPNet {
	t.Helper()
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("bad test cidr %q: %v", s, err)
	}
	n.IP = ip // keep the host address, the way iface.Addrs() reports it
	return *n
}

func lan(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("bad test lan %q: %v", s, err)
	}
	return n
}

// The vehicle's real shape: two WAN modems, the LAN side, the tunnel, and
// loopback. Only the two modems should be built into paths, and in a stable
// name order so their ids survive a reboot.
func TestSelectsWANUplinksOnly(t *testing.T) {
	ifaces := []Iface{
		{Name: "lo", Loopback: true, Up: true, Addrs: []net.IPNet{cidr(t, "127.0.0.1/8")}},
		{Name: "eth0", Up: true, Addrs: []net.IPNet{cidr(t, "10.0.0.1/24")}},        // LAN side
		{Name: "enp2s0", Up: true, Addrs: []net.IPNet{cidr(t, "192.168.8.100/24")}}, // modem
		{Name: "enp1s0", Up: true, Addrs: []net.IPNet{cidr(t, "100.72.0.5/16")}},    // modem (CGNAT)
		{Name: "wg0", Up: true, Addrs: []net.IPNet{cidr(t, "10.30.0.2/24")}},        // tunnel
	}
	got, reasons := Select(ifaces, lan(t, "10.0.0.0/24"), "wg0")
	want := []string{"enp1s0", "enp2s0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("selected %v, want %v (reasons: %v)", got, want, reasons)
	}
}

// The Wi-Fi lifeline shares the LAN subnet by design, so the LAN exclusion
// must cover it: pinning a path to the lifeline would put project traffic on
// the one link that has to stay clear for recovery.
func TestLifelineOnLANIsNotAnUplink(t *testing.T) {
	ifaces := []Iface{
		{Name: "wlan0", Up: true, Addrs: []net.IPNet{cidr(t, "10.0.0.237/24")}},
		{Name: "enp1s0", Up: true, Addrs: []net.IPNet{cidr(t, "100.72.0.5/16")}},
	}
	got, reasons := Select(ifaces, lan(t, "10.0.0.0/24"), "wg0")
	if want := []string{"enp1s0"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("selected %v, want %v", got, want)
	}
	if reasons["wlan0"] == "" {
		t.Fatal("no reason recorded for excluding the lifeline")
	}
}

// A cellular interface that is up but still holds only the 169.254 address
// DHCP has not yet replaced is not reachable on anything, and must not be
// taken for a usable uplink.
func TestLinkLocalOnlyIsNotUsable(t *testing.T) {
	ifaces := []Iface{
		{Name: "wwan0", Up: true, Addrs: []net.IPNet{cidr(t, "169.254.3.4/16")}},
	}
	if got, _ := Select(ifaces, lan(t, "10.0.0.0/24"), "wg0"); len(got) != 0 {
		t.Fatalf("selected %v from a link-local-only interface, want none", got)
	}
}

// An IPv6-only interface reads as unusable: the sockets and the home
// endpoint are v4, so v6 alone is no way out (D-026 keeps v6 off the WAN).
func TestIPv6OnlyIsNotUsable(t *testing.T) {
	ifaces := []Iface{
		{Name: "enp1s0", Up: true, Addrs: []net.IPNet{cidr(t, "2001:db8::5/64")}},
	}
	if got, _ := Select(ifaces, nil, "wg0"); len(got) != 0 {
		t.Fatalf("selected %v from a v6-only interface, want none", got)
	}
}

// An addressed WAN link that is administratively down is left out rather
// than built into a path that is down from birth.
func TestDownInterfaceIsExcluded(t *testing.T) {
	ifaces := []Iface{
		{Name: "enp1s0", Up: false, Addrs: []net.IPNet{cidr(t, "100.72.0.5/16")}},
	}
	got, reasons := Select(ifaces, nil, "wg0")
	if len(got) != 0 {
		t.Fatalf("selected the down interface: %v", got)
	}
	if reasons["enp1s0"] == "" {
		t.Fatal("no reason recorded for the down interface")
	}
}

// Common virtual interfaces are never uplinks even when up and addressed,
// so an RV that happens to run containers or a second tunnel does not sprout
// phantom paths.
func TestVirtualInterfacesAreExcluded(t *testing.T) {
	for _, name := range []string{"docker0", "br-abc123", "veth9f2", "tailscale0", "omp0", "virbr0"} {
		ifaces := []Iface{{Name: name, Up: true, Addrs: []net.IPNet{cidr(t, "172.17.0.1/16")}}}
		if got, _ := Select(ifaces, nil, "wg0"); len(got) != 0 {
			t.Errorf("%s was taken for an uplink: %v", name, got)
		}
	}
}

// With no LAN given the exclusion is simply skipped rather than panicking on
// a nil subnet - a caller may not know the LAN.
func TestNilLANSkipsThatExclusion(t *testing.T) {
	ifaces := []Iface{{Name: "eth0", Up: true, Addrs: []net.IPNet{cidr(t, "10.0.0.1/24")}}}
	if got, _ := Select(ifaces, nil, "wg0"); len(got) != 1 {
		t.Fatalf("selected %v with no LAN filter, want eth0 kept", got)
	}
}

// The real RV, dumped from the running vehicle (2026-09-06): loopback, the
// LAN side, two WAN modems (one on CGNAT, one behind a router), the two
// transport tunnels and the D-020 TUN. Auto-detect must land on exactly the
// two modems - the same list the vehicle was being run with by hand - and
// nothing else. This is the "validate against the real use case" check; the
// synthetic cases above are the reasoning, this is the ground truth.
func TestRealVehicleShape(t *testing.T) {
	ifaces := []Iface{
		{Name: "lo", Loopback: true, Up: true, Addrs: []net.IPNet{cidr(t, "127.0.0.1/8")}},
		{Name: "eth0", Up: true, Addrs: []net.IPNet{cidr(t, "10.0.0.1/24")}},
		{Name: "enp1s0", Up: true, Addrs: []net.IPNet{cidr(t, "100.110.247.30/10")}},
		{Name: "enp2s0", Up: true, Addrs: []net.IPNet{cidr(t, "192.168.225.3/22")}},
		{Name: "wg1", Up: true, Addrs: []net.IPNet{cidr(t, "10.20.1.2/32")}},
		{Name: "wg2", Up: true, Addrs: []net.IPNet{cidr(t, "10.20.1.3/32")}},
		{Name: "omp0", Up: true, Addrs: []net.IPNet{cidr(t, "10.30.0.2/24")}},
	}
	got, reasons := Select(ifaces, lan(t, "10.0.0.0/24"), "wg0")
	if want := []string{"enp1s0", "enp2s0"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("selected %v, want %v\nreasons: %v", got, want, reasons)
	}
}

// Above WireGuard (D-020) the daemon's paths are the wg transports, not the
// physical NICs. Selecting the NICs there would point the daemon at home's
// inner address over a link that cannot reach it - the stranding this split
// exists to prevent. On the real RV that is exactly wg1, wg2, and never the
// modems, the LAN, or the daemon's own omp0 TUN.
func TestTransportsPickWireGuardNotNICs(t *testing.T) {
	ifaces := []Iface{
		{Name: "lo", Loopback: true, Up: true, Addrs: []net.IPNet{cidr(t, "127.0.0.1/8")}},
		{Name: "eth0", Up: true, Addrs: []net.IPNet{cidr(t, "10.0.0.1/24")}},
		{Name: "enp1s0", Up: true, Addrs: []net.IPNet{cidr(t, "100.110.247.30/10")}},
		{Name: "enp2s0", Up: true, Addrs: []net.IPNet{cidr(t, "192.168.225.3/22")}},
		{Name: "wg1", Up: true, PointToPoint: true, Addrs: []net.IPNet{cidr(t, "10.20.1.2/32")}},
		{Name: "wg2", Up: true, PointToPoint: true, Addrs: []net.IPNet{cidr(t, "10.20.1.3/32")}},
		{Name: "omp0", Up: true, PointToPoint: true, Addrs: []net.IPNet{cidr(t, "10.30.0.2/24")}},
	}
	got, reasons := SelectTransports(ifaces, "omp0")
	if want := []string{"wg1", "wg2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("selected %v, want %v\nreasons: %v", got, want, reasons)
	}
}

// The daemon's own TUN is a point-to-point device with a wg-ish role but must
// never be selected as one of its own transports.
func TestTransportsExcludeOwnTun(t *testing.T) {
	ifaces := []Iface{
		{Name: "wg1", Up: true, PointToPoint: true},
		{Name: "wg0", Up: true, PointToPoint: true}, // if it were the daemon's own
	}
	got, _ := SelectTransports(ifaces, "wg0")
	if want := []string{"wg1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("selected %v, want %v", got, want)
	}
}

// A down transport is left out, the same as a down uplink: a path that is
// down from birth is worse than one an operator meant to leave off.
func TestTransportsExcludeDown(t *testing.T) {
	ifaces := []Iface{
		{Name: "wg1", Up: true, PointToPoint: true},
		{Name: "wg2", Up: false, PointToPoint: true},
	}
	if got, _ := SelectTransports(ifaces, "omp0"); !reflect.DeepEqual(got, []string{"wg1"}) {
		t.Fatalf("selected %v, want [wg1]", got)
	}
}
