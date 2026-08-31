package relay

import (
	"testing"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

// Readings are held against the peer's clock, so when the peer restarts
// that clock jumps back to zero and everything measured against it becomes
// fiction. Left undetected this showed up as a p95 spread of 196 seconds -
// exactly how long the far end had been up before it was restarted.
func TestPeerRestartResetsDelayMeasurements(t *testing.T) {
	var s pathStats

	for i := 0; i < 50; i++ {
		s.observeTransit(1_000_000+uint32(i%3)*100, time.Duration(i)*time.Millisecond)
	}
	if s.spread() > 10_000 {
		t.Fatalf("spread = %d before any restart, want a small figure", s.spread())
	}

	// The peer comes back with its clock at zero, so transit shifts by
	// however long it had been up. The subtraction is meant to wrap, so it
	// has to happen at run time rather than as a constant expression.
	uptime := uint32(200 * time.Second / time.Microsecond)
	after := uint32(1_000_000) - uptime

	if restarted := s.observeTransit(after, 51*time.Millisecond); !restarted {
		t.Fatal("a 200 second shift in transit was not recognised as a restart")
	}

	for i := 52; i < 100; i++ {
		s.observeTransit(after+uint32(i%3)*100, time.Duration(i)*time.Millisecond)
	}
	if got := s.spread(); got > 10_000 {
		t.Errorf("spread = %d (%.1f s) after the restart settled, want a small figure",
			got, float64(got)/1e6)
	}
	if got := s.jitter; got > 10_000 {
		t.Errorf("jitter = %.0f after the restart settled, want a small figure", got)
	}
}

// Ordinary network delay, even the couple of seconds a carrier can hold in
// its own buffer, must never be mistaken for a restart.
func TestLargeQueueIsNotMistakenForRestart(t *testing.T) {
	var s pathStats
	s.observeTransit(1_000_000, 0)

	if restarted := s.observeTransit(1_000_000+uint32(2*time.Second/time.Microsecond),
		time.Millisecond); restarted {
		t.Error("two seconds of queue was treated as a peer restart")
	}
}

// A peer restart also takes its sequence counters back to zero. Without
// noticing, every subsequent packet reads as ancient against the counter
// we were expecting and sequence tracking never recovers.
func TestPeerRestartRecoversSequenceTracking(t *testing.T) {
	s := newTestSession()

	// Establish a run at a high sequence, from a peer that has been up for
	// a while.
	uptime := uint32(200 * time.Second / time.Microsecond)
	for i := uint32(0); i < 10; i++ {
		s.observe(&protocol.Header{PathID: 0, PathSeq: 4000 + i, SendTS: uptime + i}, 100)
	}
	before := s.paths[0].stats.received

	// The peer restarts: its clock and its sequence both start over, so
	// its timestamps drop from that uptime back to nearly nothing.
	for i := uint32(0); i < 10; i++ {
		s.observe(&protocol.Header{PathID: 0, PathSeq: i, SendTS: 1000 + i}, 100)
	}

	got := s.paths[0].stats.received - before
	if got != 10 {
		t.Errorf("counted %d packets after the restart, want 10", got)
	}
	// The restart must not be booked as a huge run of loss.
	if lost := s.paths[0].stats.lost; lost != 0 {
		t.Errorf("lost = %d across a peer restart, want 0", lost)
	}
	if want := uint32(10); s.paths[0].wantSeq != want {
		t.Errorf("next expected sequence = %d, want %d; tracking did not re-baseline",
			s.paths[0].wantSeq, want)
	}
}
