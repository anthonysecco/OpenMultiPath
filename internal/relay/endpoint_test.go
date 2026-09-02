package relay

import (
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

func udpPair(t *testing.T) (*net.UDPConn, *net.UDPConn) {
	t.Helper()
	a, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen a: %v", err)
	}
	t.Cleanup(func() { a.Close() })
	b, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen b: %v", err)
	}
	t.Cleanup(func() { b.Close() })
	return a, b
}

// The responder knows WireGuard's listen address up front, so it writes
// there without waiting to be spoken to first.
func TestLoopbackEndpointWritesToItsFixedTarget(t *testing.T) {
	conn, wg := udpPair(t)
	e := &loopbackEndpoint{conn: conn, target: wg.LocalAddr().(*net.UDPAddr)}

	if err := e.write([]byte("payload")); err != nil {
		t.Fatalf("write: %v", err)
	}

	wg.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, _, err := wg.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("the payload never arrived: %v", err)
	}
	if got := string(buf[:n]); got != "payload" {
		t.Errorf("got %q, want %q", got, "payload")
	}
}

// The initiator cannot know the address in advance: WireGuard picks an
// ephemeral source port. So the endpoint learns it from the first packet
// WireGuard sends and replies there afterwards. This is the behaviour the
// loopback relay has always had, and it has to survive being moved behind
// an interface, because it is the way back from D-020.
func TestLoopbackEndpointLearnsThePeerItReplyTo(t *testing.T) {
	conn, wg := udpPair(t)
	e := &loopbackEndpoint{conn: conn} // no target: learn it

	// Before anything has been heard, a write has nowhere to go. It must
	// be dropped rather than reported as an error - the tunnel simply is
	// not up yet.
	if err := e.write([]byte("too early")); err != nil {
		t.Errorf("write before the peer is known returned %v, want it silently dropped", err)
	}

	got := make(chan string, 1)
	go e.readPayloads("test", func(p []byte) { got <- string(p) })

	if _, err := wg.WriteToUDP([]byte("from wireguard"), conn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("write from the wireguard side: %v", err)
	}
	select {
	case p := <-got:
		if p != "from wireguard" {
			t.Errorf("read %q, want %q", p, "from wireguard")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("readPayloads never delivered the packet")
	}

	// Now the address is known, the reply must reach it.
	if err := e.write([]byte("reply")); err != nil {
		t.Fatalf("write after learning the peer: %v", err)
	}
	wg.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, _, err := wg.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("the reply never came back: %v", err)
	}
	if string(buf[:n]) != "reply" {
		t.Errorf("reply was %q, want %q", buf[:n], "reply")
	}
}

func TestTunConfigIsOffUnlessNamed(t *testing.T) {
	if (TunConfig{}).Enabled() {
		t.Error("an empty TunConfig reported enabled; the loopback relay must be the default")
	}
	if !(TunConfig{Name: "omp0"}).Enabled() {
		t.Error("a named TunConfig reported disabled")
	}
}

// D-020's endpoint, end to end: a packet routed into the device comes out
// of readPayloads, and a packet handed to write reaches the host stack.
func TestTunEndpointCarriesPacketsBothWays(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a tun device")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("no /dev/net/tun on this machine")
	}

	e, err := openTun(TunConfig{Name: "ompep0", Addr: "10.99.95.1/24", MTU: 1300})
	if err != nil {
		t.Skipf("cannot create tun device here: %v", err)
	}
	defer e.Close()

	if e.mtu != 1300 {
		t.Errorf("endpoint reports mtu %d, want 1300", e.mtu)
	}

	// Outbound: something the host routes at the device must surface as a
	// payload. Housekeeping packets the kernel emits arrive too, so look
	// for the one this test caused rather than taking the first.
	payloads := make(chan []byte, 64)
	go e.readPayloads("test-tun", func(p []byte) {
		cp := append([]byte(nil), p...)
		select {
		case payloads <- cp:
		default:
		}
	})

	go func() {
		time.Sleep(150 * time.Millisecond)
		c, err := net.Dial("udp", "10.99.95.2:7777")
		if err != nil {
			return
		}
		defer c.Close()
		c.Write([]byte("outbound"))
	}()

	deadline := time.After(8 * time.Second)
	var found bool
	for !found {
		select {
		case p := <-payloads:
			if len(p) < 20 || p[0]>>4 != 4 || p[9] != 17 {
				continue // kernel housekeeping, not ours
			}
			if netip.AddrFrom4([4]byte(p[16:20])) != netip.MustParseAddr("10.99.95.2") {
				continue
			}
			if got := string(p[28:]); got != "outbound" {
				t.Errorf("payload is %q, want %q", got, "outbound")
			}
			found = true
		case <-deadline:
			t.Fatal("the packet routed into the device never came out as a payload")
		}
	}

	// Inbound: a payload written to the endpoint must reach a socket, the
	// way a packet arriving from home does.
	pc, err := net.ListenPacket("udp", "10.99.95.1:7778")
	if err != nil {
		t.Fatalf("listen on the tunnel address: %v", err)
	}
	defer pc.Close()

	if err := e.write(testUDPPacket("10.99.95.2", 4444, "10.99.95.1", 7778, []byte("inbound"))); err != nil {
		t.Fatalf("write: %v", err)
	}
	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 128)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("the payload written to the endpoint never reached the stack: %v", err)
	}
	if got := string(buf[:n]); got != "inbound" {
		t.Errorf("got %q, want %q", got, "inbound")
	}
}

func testUDPPacket(srcIP string, sport int, dstIP string, dport int, payload []byte) []byte {
	total := 20 + 8 + len(payload)
	p := make([]byte, total)
	p[0] = 4<<4 | 5
	p[2], p[3] = byte(total>>8), byte(total)
	p[8], p[9] = 64, 17
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
