package classify

import (
	"net/netip"
	"testing"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

func className(c uint8) string {
	switch c {
	case protocol.ClassRealtime:
		return "realtime"
	case protocol.ClassBulk:
		return "bulk"
	default:
		return "unknown"
	}
}

// The claim that makes STUN the primary classifier: it fires on the flow's
// very first packet, before any media has been sent. Every other signal is
// retrospective, and a call classified retrospectively has already spent
// that time on the wrong path.
func TestSTUNClassifiesBeforeAnyMediaFlows(t *testing.T) {
	c, _ := testClassifier(t)

	got := c.Classify(udp4("10.20.0.2", 51234, "142.250.1.1", 19302, stunBinding(), 0))

	if got != protocol.ClassRealtime {
		t.Fatalf("a STUN binding request classified %s, want realtime;"+
			" the ICE check is the announcement that media is about to use this 5-tuple", className(got))
	}
}

// ICE sends its connectivity checks from the exact port pair the media will
// use, so the media that follows must inherit the class without being
// re-examined - it looks like nothing in particular on its own.
func TestMediaInheritsTheClassSTUNEstablished(t *testing.T) {
	c, clk := testClassifier(t)
	c.Classify(udp4("10.20.0.2", 51234, "142.250.1.1", 19302, stunBinding(), 0))

	// Media that is neither small nor metronomic, so the behavioural
	// heuristic would not have called it real-time on its own.
	for i := 0; i < 40; i++ {
		clk.add(time.Duration(3+i%17) * time.Millisecond)
		got := c.Classify(udp4("10.20.0.2", 51234, "142.250.1.1", 19302, nil, 1300))
		if got != protocol.ClassRealtime {
			t.Fatalf("media packet %d on a STUN-established flow classified %s, want realtime", i, className(got))
		}
	}
}

// A call is one conversation with traffic both ways. If the reply half were
// keyed separately, inbound audio could be real-time while outbound audio
// was bulk - the single worst way to classify a video call.
func TestReplyDirectionSharesTheClass(t *testing.T) {
	c, _ := testClassifier(t)
	c.Classify(udp4("10.20.0.2", 51234, "142.250.1.1", 19302, stunBinding(), 0))

	got := c.Classify(udp4("142.250.1.1", 19302, "10.20.0.2", 51234, nil, 200))

	if got != protocol.ClassRealtime {
		t.Fatalf("the reply direction classified %s, want realtime; a flow and its reply are one conversation", className(got))
	}
	if n := c.Flows(); n != 1 {
		t.Errorf("a bidirectional conversation occupies %d cache entries, want 1", n)
	}
}

// D-018, and the reason a blanket UDP rule was rejected: QUIC carries an
// enormous volume of bulk on UDP/443. Classifying it real-time would
// duplicate YouTube across a metered link.
func TestQUICBulkOnUDP443IsNotRealtime(t *testing.T) {
	c, clk := testClassifier(t)

	var got uint8
	for i := 0; i < 60; i++ {
		// MTU-sized and bursty: a tight run of packets, then a pause.
		if i%8 == 0 {
			clk.add(90 * time.Millisecond)
		} else {
			clk.add(time.Millisecond)
		}
		got = c.Classify(udp4("10.20.0.2", 44001, "142.250.1.1", 443, nil, 1350))
	}

	if got != protocol.ClassBulk {
		t.Fatalf("MTU-sized bursty UDP/443 classified %s, want bulk;"+
			" this is the YouTube-over-QUIC case D-018 exists for", className(got))
	}
}

// The other half of the heuristic: a native conferencing client that never
// speaks ICE and has no vendor prefix must still be found, from shape alone.
func TestMetronomicSmallUDPIsRealtime(t *testing.T) {
	c, clk := testClassifier(t)

	var got uint8
	for i := 0; i < 60; i++ {
		clk.add(20 * time.Millisecond) // codec cadence
		got = c.Classify(udp4("10.20.0.2", 8801, "3.7.35.1", 8801, nil, 180))
	}

	if got != protocol.ClassRealtime {
		t.Fatalf("small metronomic UDP classified %s, want realtime;"+
			" protocol.md's claim is that nothing but media looks like this", className(got))
	}
}

// Both signals have to agree. Small alone is not enough - DNS, keepalives
// and game control channels are all small and none of them is a call.
func TestSmallButRaggedIsNotRealtime(t *testing.T) {
	c, clk := testClassifier(t)

	var got uint8
	for i := 0; i < 60; i++ {
		clk.add(time.Duration(2+(i*37)%240) * time.Millisecond)
		got = c.Classify(udp4("10.20.0.2", 5353, "1.1.1.1", 53, nil, 90))
	}

	if got != protocol.ClassBulk {
		t.Fatalf("small but ragged UDP classified %s, want bulk; size alone does not make a call", className(got))
	}
}

// And metronomic alone is not enough either: a constant-bitrate download
// is regular and fat, and duplicating it would be exactly the mistake.
func TestMetronomicButFatIsNotRealtime(t *testing.T) {
	c, clk := testClassifier(t)

	var got uint8
	for i := 0; i < 60; i++ {
		clk.add(20 * time.Millisecond)
		got = c.Classify(udp4("10.20.0.2", 44002, "142.250.1.1", 443, nil, 1350))
	}

	if got != protocol.ClassBulk {
		t.Fatalf("metronomic MTU-sized UDP classified %s, want bulk; cadence alone does not make a call", className(got))
	}
}

// protocol.md's free first-pass exclusion. Shape must not get a vote:
// a TCP flow that happens to look metronomic and small is still not a call.
func TestTCPIsNeverRealtime(t *testing.T) {
	c, clk := testClassifier(t)

	for i := 0; i < 60; i++ {
		clk.add(20 * time.Millisecond)
		if got := c.Classify(tcp4("10.20.0.2", 40001, "142.250.1.1", 443, 120)); got != protocol.ClassBulk {
			t.Fatalf("TCP packet %d classified %s, want bulk unconditionally", i, className(got))
		}
	}
	if n := c.Flows(); n != 0 {
		t.Errorf("TCP occupied %d flow cache entries, want none; it is decided without being remembered", n)
	}
}

// The safe default while evidence is still being gathered. Guessing
// real-time would duplicate an unidentified download over a metered link
// and reserve admission-control capacity for it.
func TestUndecidedFlowIsUnknownNotRealtime(t *testing.T) {
	c, clk := testClassifier(t)

	for i := 0; i < defaults().ClassifySamplePackets-1; i++ {
		clk.add(20 * time.Millisecond)
		if got := c.Classify(udp4("10.20.0.2", 5001, "9.9.9.9", 5001, nil, 180)); got != protocol.ClassUnknown {
			t.Fatalf("packet %d of an unproven flow classified %s, want unknown", i, className(got))
		}
	}
}

// Vendor prefixes are a hint for native clients, below STUN in precedence
// but ahead of waiting for a behavioural sample to fill.
func TestVendorPrefixClassifiesImmediately(t *testing.T) {
	c, _ := testClassifier(t)
	c.SetVendorPrefixes([]netip.Prefix{netip.MustParsePrefix("3.7.35.0/25")})

	if got := c.Classify(udp4("10.20.0.2", 9000, "3.7.35.1", 8801, nil, 1300)); got != protocol.ClassRealtime {
		t.Fatalf("a flow to a vendor prefix classified %s, want realtime", className(got))
	}
}

// Port pairs get reused. A new conversation on a recycled 5-tuple must not
// inherit the last one's class, or a download lands on the call's path.
func TestIdleFlowExpiresSoAReusedPortStartsClean(t *testing.T) {
	c, clk := testClassifier(t)
	c.Classify(udp4("10.20.0.2", 51234, "142.250.1.1", 19302, stunBinding(), 0))

	clk.add(time.Duration(defaults().ClassifyFlowIdleSeconds)*time.Second + time.Second)

	if got := c.Classify(udp4("10.20.0.2", 51234, "142.250.1.1", 19302, nil, 1300)); got == protocol.ClassRealtime {
		t.Fatalf("a reused port pair inherited realtime from an expired flow")
	}
}

// The table is a memory bound on a box that has to survive months without
// a reboot. It must not grow without limit under a port scan or a busy
// household.
func TestFlowTableStaysBounded(t *testing.T) {
	c, clk := testClassifier(t)
	maxFlows := defaults().ClassifyMaxFlows

	for i := 0; i < maxFlows+5_000; i++ {
		clk.add(time.Millisecond)
		c.Classify(udp4("10.20.0.2", 1024+i%60000, "142.250.1.1", uint16port(i), nil, 400))
	}

	if n := c.Flows(); n > maxFlows {
		t.Fatalf("flow table holds %d entries, above the %d ceiling", n, maxFlows)
	}
}

func uint16port(i int) int { return 1024 + (i*7919)%60000 }

// Nothing the LAN can send should panic the daemon or be silently called
// real-time. Principle 5: fail to a working state.
func TestMalformedPacketsAreUnknownNotAPanic(t *testing.T) {
	c, _ := testClassifier(t)

	cases := map[string][]byte{
		"empty":            {},
		"one byte":         {0x45},
		"truncated ipv4":   {0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17},
		"bad version":      {0x95, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8},
		"icmp not tcp/udp": ip4("10.20.0.2", "1.1.1.1", 1, make([]byte, 8)),
		"udp header cut":   ip4("10.20.0.2", "1.1.1.1", protoUDP, []byte{0, 53, 0, 53}),
		"ihl below min":    {0x44, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8},
	}

	for name, pkt := range cases {
		if got := c.Classify(pkt); got != protocol.ClassUnknown {
			t.Errorf("%s classified %s, want unknown", name, className(got))
		}
	}
}

// A non-first fragment carries no ports, so it cannot be attributed to a
// conversation at all. Guessing would be worse than admitting it.
func TestTrailingFragmentIsUnknown(t *testing.T) {
	c, _ := testClassifier(t)
	pkt := udp4("10.20.0.2", 51234, "142.250.1.1", 19302, stunBinding(), 0)
	pkt[6], pkt[7] = 0x00, 0x20 // fragment offset, non-zero

	if got := c.Classify(pkt); got != protocol.ClassUnknown {
		t.Errorf("a trailing fragment classified %s, want unknown", className(got))
	}
}
