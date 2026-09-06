package classify

import (
	"testing"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

// send pushes a flow at roughly kbps for a duration, and returns the last
// class it was given.
func send(c *Classifier, clk *clock, port, kbps int, d time.Duration) uint8 {
	const size = 1200
	// Packets per second needed to hit the rate, and the gap between them.
	pps := float64(kbps*1000) / float64(size*8)
	if pps < 1 {
		pps = 1
	}
	gap := time.Duration(float64(time.Second) / pps)

	var got uint8
	for elapsed := time.Duration(0); elapsed < d; elapsed += gap {
		clk.add(gap)
		got = c.Classify(tcp4("10.20.0.2", port, "142.250.1.1", 443, size))
	}
	return got
}

// The case the class exists for. A page load is a burst of a second or
// two and then idle; it must not be exiled onto the slow link for that.
func TestPageLoadBurstStaysTransactional(t *testing.T) {
	c, clk := testClassifier(t)

	// Well above the demote rate, but only for a second - shorter than
	// the dwell.
	got := send(c, clk, 40100, 8000, time.Second)

	if got != protocol.ClassTransactional {
		t.Errorf("a one second burst classified %s, want transactional;"+
			" the dwell is what separates a page load from a download", className(got))
	}
}

// And the case it must not break: a sustained transfer is bulk.
func TestSustainedTransferBecomesBulk(t *testing.T) {
	c, clk := testClassifier(t)

	got := send(c, clk, 40200, 8000, 6*time.Second)

	if got != protocol.ClassBulk {
		t.Errorf("six seconds at 8 Mbps classified %s, want bulk", className(got))
	}
}

// A flow that stops moving volume goes back to transactional. HTTP/2 and
// HTTP/3 multiplex a download and then interactive requests onto one
// connection, so a one-way demotion would make every page slow after the
// first large object.
func TestFlowReturnsToTransactionalWhenTheTransferEnds(t *testing.T) {
	c, clk := testClassifier(t)

	if got := send(c, clk, 40300, 8000, 6*time.Second); got != protocol.ClassBulk {
		t.Fatalf("setup: flow is %s, want bulk", className(got))
	}

	// Now trickle, below the clear threshold, for longer than the clear
	// dwell.
	got := send(c, clk, 40300, 100, 8*time.Second)

	if got != protocol.ClassTransactional {
		t.Errorf("a flow that went quiet is still %s, want transactional again", className(got))
	}
}

// Hysteresis: the promote threshold is lower than the demote one, so a
// download that dips briefly does not flap between classes - and every
// flap would move it between paths, reordering it.
func TestBriefDipDoesNotPromoteABulkFlow(t *testing.T) {
	c, clk := testClassifier(t)

	if got := send(c, clk, 40400, 8000, 6*time.Second); got != protocol.ClassBulk {
		t.Fatalf("setup: flow is %s, want bulk", className(got))
	}

	// Below the demote rate but above the clear rate, and for less than
	// the clear dwell either way.
	if got := send(c, clk, 40400, 1500, 2*time.Second); got != protocol.ClassBulk {
		t.Errorf("a brief dip promoted the flow to %s; the clear threshold is lower for a reason", className(got))
	}
}

// The backstop, for a transfer fast enough to move serious volume inside
// the dwell window.
func TestVeryFastTransferIsCaughtByTheByteBackstop(t *testing.T) {
	c, clk := testClassifier(t)
	cfg := defaults()

	// Push past ClassifyBulkBytes in well under the dwell.
	sent := 0
	var got uint8
	for sent < cfg.ClassifyBulkBytes+(1<<20) {
		clk.add(time.Millisecond)
		got = c.Classify(tcp4("10.20.0.2", 40500, "142.250.1.1", 443, 1400))
		sent += 1400
	}

	if got != protocol.ClassBulk {
		t.Errorf("%d MB moved inside the dwell classified %s, want bulk",
			sent>>20, className(got))
	}
}

// DNS is named rather than inferred: resolution latency is felt directly
// in every page load, and waiting for a behavioural sample to place a
// handful of 80-byte lookups is the wrong answer for the one flow whose
// latency the user notices most.
func TestDNSIsTransactionalImmediately(t *testing.T) {
	c, _ := testClassifier(t)

	if got := c.Classify(udp4("10.20.0.2", 41000, "1.1.1.1", 53, nil, 80)); got != protocol.ClassTransactional {
		t.Errorf("first DNS packet classified %s, want transactional", className(got))
	}
}

// A call is still a call. The volume detector must never be able to
// overturn a real-time verdict - that is the one class it does not
// arbitrate.
func TestVolumeNeverDemotesACall(t *testing.T) {
	c, clk := testClassifier(t)

	// STUN settles it as real-time on the first packet.
	if got := c.Classify(udp4("10.20.0.2", 42000, "5.6.7.8", 3478, stunBinding(), 200)); got != protocol.ClassRealtime {
		t.Fatalf("setup: STUN did not classify real-time")
	}

	// Then push a great deal of volume through the same flow.
	var got uint8
	for i := 0; i < 20000; i++ {
		clk.add(time.Millisecond)
		got = c.Classify(udp4("10.20.0.2", 42000, "5.6.7.8", 3478, nil, 1400))
	}

	if got != protocol.ClassRealtime {
		t.Errorf("a call carrying video was demoted to %s", className(got))
	}
}

// The thresholds are guesses and have to be adjustable, which means the
// detector must read them rather than bake them in.
func TestThresholdsAreAdjustable(t *testing.T) {
	cfg := defaults()
	cfg.ClassifyBulkKbps = 64
	cfg.ClassifyBulkDwellMs = 200

	clk := newClock()
	c := New(config.NewHolder(cfg))
	c.now = clk.now

	if got := send(c, clk, 40600, 2000, 2*time.Second); got != protocol.ClassBulk {
		t.Errorf("with a 64 kbps/200 ms threshold a 2 Mbps flow is %s, want bulk", className(got))
	}

	// And loosened the other way, the same flow stays transactional.
	loose := defaults()
	loose.ClassifyBulkKbps = 500000
	loose.ClassifyBulkDwellMs = 60000
	loose.ClassifyBulkBytes = 1 << 30

	clk2 := newClock()
	c2 := New(config.NewHolder(loose))
	c2.now = clk2.now

	if got := send(c2, clk2, 40700, 20000, 10*time.Second); got != protocol.ClassTransactional {
		t.Errorf("with the thresholds raised a 20 Mbps flow is %s, want transactional", className(got))
	}
}
