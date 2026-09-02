package classify

import (
	"net/netip"
	"testing"
)

// The key must be canonical: a packet and its reply are one conversation,
// distinguished only by the direction reported alongside it.
func TestReplyProducesTheSameKeyAndTheOppositeDirection(t *testing.T) {
	out, ok := parse(udp4("10.20.0.2", 51234, "142.250.1.1", 19302, nil, 200))
	if !ok {
		t.Fatal("outbound packet did not parse")
	}
	in, ok := parse(udp4("142.250.1.1", 19302, "10.20.0.2", 51234, nil, 200))
	if !ok {
		t.Fatal("inbound packet did not parse")
	}

	if out.flow != in.flow {
		t.Errorf("a packet and its reply produced different keys:\n out %+v\n in  %+v", out.flow, in.flow)
	}
	if out.dir == in.dir {
		t.Errorf("a packet and its reply reported the same direction %v", out.dir)
	}
}

// Same ports both ways is the normal case for RTP, and the one where a
// naive canonicalisation collapses direction entirely.
func TestSymmetricPortsStillDistinguishDirection(t *testing.T) {
	a, _ := parse(udp4("10.20.0.2", 8801, "3.7.35.1", 8801, nil, 180))
	b, _ := parse(udp4("3.7.35.1", 8801, "10.20.0.2", 8801, nil, 180))

	if a.flow != b.flow {
		t.Error("symmetric-port packets produced different keys")
	}
	if a.dir == b.dir {
		t.Error("symmetric-port packets reported the same direction")
	}
}

func TestFiveTupleIsExtracted(t *testing.T) {
	p, ok := parse(udp4("10.20.0.2", 51234, "142.250.1.1", 19302, nil, 200))
	if !ok {
		t.Fatal("packet did not parse")
	}
	want := netip.MustParseAddr("10.20.0.2")
	if p.flow.A != want || p.flow.APort != 51234 {
		t.Errorf("endpoint A is %v:%d, want %v:51234", p.flow.A, p.flow.APort, want)
	}
	if p.flow.Proto != protoUDP {
		t.Errorf("protocol is %d, want %d", p.flow.Proto, protoUDP)
	}
	if p.size != 200 {
		t.Errorf("size is %d, want the full inner packet length of 200", p.size)
	}
}

// The payload offset has to be right or STUN is looked for in the wrong
// place - and a header byte that happened to hold the cookie would be a
// false positive on the primary classifier.
func TestUDPPayloadStartsAfterTheHeaders(t *testing.T) {
	p, ok := parse(udp4("10.20.0.2", 51234, "142.250.1.1", 19302, stunBinding(), 0))
	if !ok {
		t.Fatal("packet did not parse")
	}
	if !isSTUNBinding(p.payload) {
		t.Errorf("payload of %d bytes was not the STUN message that was put there", len(p.payload))
	}
}

// TCP's data offset is variable, and options are normal on any modern
// connection.
func TestTCPOptionsAreSteppedOver(t *testing.T) {
	pkt := tcp4("10.20.0.2", 40001, "142.250.1.1", 443, 60)
	pkt[20+12] = 8 << 4 // eight words of header: 20 bytes of options
	p, ok := parse(pkt)
	if !ok {
		t.Fatal("packet with TCP options did not parse")
	}
	if want := 60 - 20 - 32; len(p.payload) != want {
		t.Errorf("payload is %d bytes, want %d; the options were not stepped over", len(p.payload), want)
	}
}

// D-026 drops IPv6 rather than carrying it, so this should not arrive.
// Parsing it anyway means that if the decision is revisited, the failure
// is a wrong class rather than no class at all.
func TestIPv6IsParsed(t *testing.T) {
	pkt := make([]byte, 40+8+20)
	pkt[0] = 6 << 4
	pkt[6] = protoUDP
	copy(pkt[8:24], netip.MustParseAddr("2001:db8::1").AsSlice())
	copy(pkt[24:40], netip.MustParseAddr("2001:db8::2").AsSlice())
	pkt[40], pkt[41] = 0xc8, 0x22 // source port 51234
	pkt[42], pkt[43] = 0x4b, 0x66 // dest port 19302
	copy(pkt[48:], stunBinding())

	p, ok := parse(pkt)
	if !ok {
		t.Fatal("an IPv6 packet did not parse")
	}
	if !p.flow.A.Is6() {
		t.Errorf("endpoint A is %v, want an IPv6 address", p.flow.A)
	}
	if !isSTUNBinding(p.payload) {
		t.Error("the IPv6 payload offset was wrong; STUN was not found where it was put")
	}
}
