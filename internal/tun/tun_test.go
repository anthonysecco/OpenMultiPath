package tun

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Creating a TUN device needs CAP_NET_ADMIN and the tun module. Neither is
// a given in a build sandbox, and a test that failed there would be
// reporting on the sandbox rather than on the code.
func requireTUN(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a tun device")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("no /dev/net/tun on this machine")
	}
}

func openTest(t *testing.T, cfg Config) *Device {
	t.Helper()
	d, err := Open(cfg)
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EBUSY) {
			t.Skipf("cannot create tun device here: %v", err)
		}
		t.Fatalf("Open(%+v): %v", cfg, err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestDeviceIsCreatedWithTheRequestedNameAndMTU(t *testing.T) {
	requireTUN(t)
	d := openTest(t, Config{Name: "omptest0", MTU: 1300, Address: netip.MustParsePrefix("10.99.99.1/24")})

	if d.Name() != "omptest0" {
		t.Errorf("device came up as %q, want omptest0", d.Name())
	}

	// Read the MTU back from the kernel rather than trusting the request.
	// A tunnel that silently kept 1500 would fragment every packet and the
	// symptom would appear a long way from here.
	got, err := d.MTU()
	if err != nil {
		t.Fatalf("MTU(): %v", err)
	}
	if got != 1300 {
		t.Errorf("kernel reports mtu %d, want the 1300 that was asked for", got)
	}

	if _, err := net.InterfaceByName("omptest0"); err != nil {
		t.Errorf("interface is not visible to the system: %v", err)
	}
}

// The load-bearing property of the whole package: a read returns one inner
// IP packet and nothing else. If IFF_NO_PI were dropped, every read would
// begin with four bytes of packet-information header, every consumer would
// silently misparse, and internal/classify would be reading an IP version
// nibble out of a flags field. So every packet that arrives is checked,
// not just the one this test sent.
//
// The device carries the kernel's own housekeeping as well as traffic that
// was routed to it - an IGMP membership report for 224.0.0.22 arrives on a
// freshly created device before anything else does. That is not a fault to
// engineer away; it is what the daemon will read, and a test that assumed
// its own packet came first would be asserting something untrue about the
// device.
func TestReadReturnsOneRawIPPacket(t *testing.T) {
	requireTUN(t)
	d := openTest(t, Config{Name: "omptest1", MTU: 1300, Address: netip.MustParsePrefix("10.99.98.1/24")})

	// Addressing the device installs an on-link route for its subnet, so
	// anything sent to a neighbour address is handed straight to us.
	go func() {
		time.Sleep(150 * time.Millisecond)
		c, err := net.Dial("udp", "10.99.98.2:9999")
		if err != nil {
			return
		}
		defer c.Close()
		c.Write([]byte("hello from the lan"))
	}()

	deadline := time.Now().Add(8 * time.Second)
	buf := make([]byte, 2048)
	var found bool

	for !found && time.Now().Before(deadline) {
		if err := d.f.SetReadDeadline(deadline); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		n, err := d.Read(buf)
		if err != nil {
			break
		}
		pkt := buf[:n]

		// Asserted on every packet, whatever it turns out to be. This is
		// the IFF_NO_PI check.
		if len(pkt) < 20 {
			t.Fatalf("read %d bytes, too short to be an IP packet", n)
		}
		if v := pkt[0] >> 4; v != 4 && v != 6 {
			t.Fatalf("first nibble is %d, which is no IP version at all;"+
				" the packet-information prefix is still there", v)
		}
		if v := pkt[0] >> 4; v == 4 {
			if total := int(pkt[2])<<8 | int(pkt[3]); total != n {
				t.Fatalf("IP total length is %d but Read returned %d bytes;"+
					" the device is handing back framing we are not accounting for", total, n)
			}
		}

		if pkt[9] != 17 {
			continue // kernel housekeeping - IGMP and the like
		}
		if dst := netip.AddrFrom4([4]byte(pkt[16:20])); dst != netip.MustParseAddr("10.99.98.2") {
			continue
		}
		found = true

		if sport := int(pkt[20])<<8 | int(pkt[21]); sport == 0 {
			t.Error("UDP source port is zero")
		}
		if dport := int(pkt[22])<<8 | int(pkt[23]); dport != 9999 {
			t.Errorf("UDP destination port is %d, want 9999", dport)
		}
		if got := string(pkt[28:n]); got != "hello from the lan" {
			t.Errorf("payload is %q, want %q", got, "hello from the lan")
		}
	}

	if !found {
		t.Error("the packet routed to the device never came back out of it")
	}
}

// A packet written to the device must reach the kernel as though it had
// arrived on the wire. This is the return direction of the tunnel: what
// the daemon does with a packet that came from home.
func TestWriteDeliversToTheKernel(t *testing.T) {
	requireTUN(t)
	d := openTest(t, Config{Name: "omptest2", MTU: 1300, Address: netip.MustParsePrefix("10.99.97.1/24")})

	pc, err := net.ListenPacket("udp", "10.99.97.1:9998")
	if err != nil {
		t.Fatalf("listen on the tunnel address: %v", err)
	}
	defer pc.Close()

	if _, err := d.Write(udpPacket("10.99.97.2", 5555, "10.99.97.1", 9998, []byte("from the tunnel"))); err != nil {
		t.Fatalf("Write: %v", err)
	}

	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 512)
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("the packet written to the device never reached the socket: %v", err)
	}
	if got := string(buf[:n]); got != "from the tunnel" {
		t.Errorf("payload is %q, want %q", got, "from the tunnel")
	}
	if !from.(*net.UDPAddr).IP.Equal(net.ParseIP("10.99.97.2")) {
		t.Errorf("packet came from %v, want 10.99.97.2", from)
	}
}

// The device must not outlive the daemon. On a box that power-cycles in a
// campground, an interface left behind by a crash is a half-configured
// state the next start has to reason about.
func TestCloseRemovesTheInterface(t *testing.T) {
	requireTUN(t)
	d, err := Open(Config{Name: "omptest3", MTU: 1300})
	if err != nil {
		t.Skipf("cannot create tun device here: %v", err)
	}
	if _, err := net.InterfaceByName("omptest3"); err != nil {
		t.Fatalf("interface was never visible: %v", err)
	}

	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := net.InterfaceByName("omptest3"); err == nil {
		t.Error("interface still exists after Close; a crash would leave it behind")
	}
}

func TestNameIsValidated(t *testing.T) {
	if _, err := Open(Config{Name: ""}); err == nil {
		t.Error("an empty device name was accepted")
	}
	if _, err := Open(Config{Name: "a-very-long-interface-name-indeed"}); err == nil {
		t.Error("an over-length device name was accepted")
	}
}

// udpPacket builds a minimal IPv4/UDP packet. The UDP checksum is left
// zero, which IPv4 permits and means "not computed".
func udpPacket(srcIP string, sport int, dstIP string, dport int, payload []byte) []byte {
	total := 20 + 8 + len(payload)
	p := make([]byte, total)
	p[0] = 4<<4 | 5
	p[2], p[3] = byte(total>>8), byte(total)
	p[8] = 64
	p[9] = 17
	copy(p[12:16], net.ParseIP(srcIP).To4())
	copy(p[16:20], net.ParseIP(dstIP).To4())

	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(p[i])<<8 | uint32(p[i+1])
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	c := ^uint16(sum)
	p[10], p[11] = byte(c>>8), byte(c)

	u := p[20:]
	u[0], u[1] = byte(sport>>8), byte(sport)
	u[2], u[3] = byte(dport>>8), byte(dport)
	l := 8 + len(payload)
	u[4], u[5] = byte(l>>8), byte(l)
	copy(u[8:], payload)
	return p
}

// D-026 keeps IPv6 off this box. A device that autoconfigured a link-local
// address would emit router solicitations and multicast listener reports,
// and the daemon would read its own kernel's chatter back out of the
// tunnel as inner packets to classify and schedule. This is not a
// theoretical tidiness argument: before the device disabled IPv6, the
// first packet out of a freshly created tun was one of exactly these.
func TestDeviceDoesNoIPv6(t *testing.T) {
	requireTUN(t)
	d := openTest(t, Config{Name: "omptest4", MTU: 1300, Address: netip.MustParsePrefix("10.99.96.1/24")})

	if b, err := os.ReadFile("/proc/sys/net/ipv6/conf/" + d.Name() + "/disable_ipv6"); err == nil {
		if got := strings.TrimSpace(string(b)); got != "1" {
			t.Errorf("disable_ipv6 is %q, want 1", got)
		}
	}

	iface, err := net.InterfaceByName(d.Name())
	if err != nil {
		t.Fatalf("InterfaceByName: %v", err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		t.Fatalf("Addrs: %v", err)
	}
	for _, a := range addrs {
		p, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		if p.Addr().Is6() {
			t.Errorf("device has IPv6 address %s; D-026 says it should have none", p)
		}
	}
}
