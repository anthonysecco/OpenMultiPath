package relay

import (
	"testing"
	"time"
)

// The two ends share no clock epoch, so transit readings carry an
// arbitrary constant offset - possibly one large enough to wrap. Queue
// delay is a difference, so the offset has to cancel completely.
func TestQueueDelayIgnoresClockOffset(t *testing.T) {
	// One modest offset and one large enough that the uint32 arithmetic
	// wraps around.
	const offsetA uint32 = 5_000
	const offsetB uint32 = 4_000_000_000

	var a, b pathStats
	transits := []uint32{1000, 1200, 5000, 1100}
	for i, d := range transits {
		now := time.Duration(i) * time.Millisecond
		a.observeTransit(offsetA+d, now)
		b.observeTransit(offsetB+d, now)
	}

	if a.queueDelay != b.queueDelay {
		t.Errorf("queue delay differs with clock offset: %d vs %d", a.queueDelay, b.queueDelay)
	}
	// The floor across the run is 1000, and the last reading is 1100.
	if want := int32(100); a.queueDelay != want {
		t.Errorf("queue delay = %d, want %d", a.queueDelay, want)
	}
}

// Without re-arming, a stale minimum - from a moment the path was
// genuinely faster, or a route that has since changed - would make an
// otherwise healthy path report standing queue forever.
func TestRollingMinimumReArms(t *testing.T) {
	var s pathStats

	// A first stretch with the floor at 1000.
	for i := 0; i < 5; i++ {
		s.observeTransit(1000, time.Duration(i)*time.Second)
	}
	if s.queueDelay != 0 {
		t.Fatalf("queue delay = %d on a flat path, want 0", s.queueDelay)
	}

	// The floor then moves up to 3000 and stays there. The old minimum
	// makes that look like 2 ms of queue until the window turns over. Two
	// windows are needed: one to stop the old minimum being current, and
	// one to fill the replacement.
	for i := 5; i < 30; i++ {
		s.observeTransit(3000, time.Duration(i)*time.Second)
	}
	if s.queueDelay != 0 {
		t.Errorf("queue delay = %d after the floor moved and settled, want 0", s.queueDelay)
	}
}

// A rate alone hides the difference between scattered loss, which
// concealment handles, and a burst, which is audible.
func TestLossBurstsAreBucketedByRunLength(t *testing.T) {
	var s pathStats

	s.observeLoss(1)
	s.observeDelivered() // isolated

	s.observeLoss(5)
	s.observeDelivered() // a run of five

	s.observeLoss(40)
	s.observeDelivered() // far past the largest bucket

	if s.bursts[0] != 1 {
		t.Errorf("single-packet bursts = %d, want 1", s.bursts[0])
	}
	if s.bursts[3] != 1 {
		t.Errorf("bursts of up to 8 = %d, want 1", s.bursts[3])
	}
	if s.bursts[len(burstBuckets)] != 1 {
		t.Errorf("oversized bursts = %d, want 1", s.bursts[len(burstBuckets)])
	}
	if s.lost != 46 {
		t.Errorf("lost = %d, want 46", s.lost)
	}
}

// Delivery with nothing outstanding must not record a zero-length burst.
func TestDeliveryWithoutLossRecordsNoBurst(t *testing.T) {
	var s pathStats
	s.observeDelivered()
	s.observeDelivered()

	for i, n := range s.bursts {
		if n != 0 {
			t.Errorf("bucket %d = %d, want 0", i, n)
		}
	}
}

// Tail latency is what sizes a jitter buffer, so the percentile has to
// reflect the spike rather than averaging it away.
func TestSpreadReflectsTailNotMean(t *testing.T) {
	var s pathStats
	// A tenth of the packets arrive far later, scattered through the run
	// the way satellite handover spikes actually fall. The averages decay
	// back between spikes and hide them; the tail is the whole story, and
	// it is the tail a jitter buffer has to be sized for.
	for i := 0; i < 100; i++ {
		transit := uint32(1000)
		if i%10 == 9 {
			transit = 50_000
		}
		s.observeTransit(transit, time.Duration(i)*time.Millisecond)
	}

	if got := s.spread(); got < 40_000 {
		t.Errorf("p95 spread = %d, want it to reflect the ~49 ms tail", got)
	}
	if mean := int32(s.ewma); mean > 20_000 {
		t.Errorf("ewma = %d; the fixture is meant to have a tail the mean hides", mean)
	}
}

func TestJitterRisesWithVariation(t *testing.T) {
	var steady, erratic pathStats
	for i := 0; i < 50; i++ {
		now := time.Duration(i) * time.Millisecond
		steady.observeTransit(1000, now)
		if i%2 == 0 {
			erratic.observeTransit(1000, now)
		} else {
			erratic.observeTransit(9000, now)
		}
	}

	if steady.jitter > 1 {
		t.Errorf("jitter on a steady path = %v, want ~0", steady.jitter)
	}
	if erratic.jitter <= steady.jitter {
		t.Errorf("jitter did not rise with variation: steady %v, erratic %v",
			steady.jitter, erratic.jitter)
	}
}

// Ten packets says nothing about a loss rate, and protocol.md is explicit
// that a path must never be promoted on statistics this thin.
func TestThinStatisticsAreFlagged(t *testing.T) {
	var s pathStats
	if !s.thin() {
		t.Error("a path with no samples is not flagged as thin")
	}
	for i := 0; i < 25; i++ {
		s.observeTransit(1000, time.Duration(i)*time.Millisecond)
	}
	if s.thin() {
		t.Error("a path with 25 samples is still flagged as thin")
	}
}
