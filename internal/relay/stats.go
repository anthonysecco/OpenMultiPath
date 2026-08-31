package relay

import (
	"sort"
	"time"
)

// sampleWindow is how many recent transit readings each path keeps for
// percentile work. protocol.md asks for roughly 200: enough for a stable
// p95, short enough to still reflect current conditions.
const sampleWindow = 200

// ewmaAlpha weights the fast-moving average. The ring buffer is the
// considered view; this is the twitchy one that state transitions watch.
const ewmaAlpha = 0.1

// jitterGain is the RFC 3550 interarrival estimator's 1/16 smoothing.
const jitterGain = 1.0 / 16.0

// minWindow is how long a rolling minimum transit reading is trusted
// before being re-armed. Without re-arming, a path that is persistently
// congested bakes its own standing queue into the baseline and then
// reports no queue delay at all.
const minWindow = 10 * time.Second

// burstBuckets groups consecutive-loss run lengths. A rate alone is
// misleading for voice: 1% loss in bursts of twenty is far worse than 1%
// scattered, because concealment covers isolated loss and not 400 ms of
// silence.
var burstBuckets = [...]int{1, 2, 4, 8, 16}

// pathStats accumulates what the scheduler will eventually score on.
//
// Every delay figure here is a *relative* transit reading: the arrival
// time on our clock minus the send timestamp on theirs. The two ends share
// no epoch, so that number is meaningless in absolute terms. It is still
// exactly right for jitter and queue delay, both of which are differences
// in which the constant offset cancels. Readings are held against the
// first one seen on the path so the arithmetic stays in a signed range.
type pathStats struct {
	haveBaseline bool
	baseline     uint32

	samples [sampleWindow]int32
	next    int
	filled  int

	ewma     float64
	haveEWMA bool

	jitter   float64
	lastRel  int32
	haveLast bool

	// Rolling minimum, kept as a current and a next so re-arming does not
	// need the full sample history.
	windowMin   int32
	nextMin     int32
	haveMin     bool
	windowStart time.Duration

	queueDelay int32 // most recent reading above the rolling minimum

	bursts   [len(burstBuckets) + 1]uint64
	runLen   int // consecutive losses currently accumulating
	received uint64
	lost     uint64
}

// observeTransit folds one arrival into the statistics. transit is the raw
// mixed-clock reading; now is our own elapsed time, used only to age the
// rolling minimum window.
func (s *pathStats) observeTransit(transit uint32, now time.Duration) {
	if !s.haveBaseline {
		s.haveBaseline = true
		s.baseline = transit
		s.windowStart = now
	}
	rel := int32(transit - s.baseline)

	s.samples[s.next] = rel
	s.next = (s.next + 1) % sampleWindow
	if s.filled < sampleWindow {
		s.filled++
	}

	if s.haveEWMA {
		s.ewma += ewmaAlpha * (float64(rel) - s.ewma)
	} else {
		s.ewma = float64(rel)
		s.haveEWMA = true
	}

	// RFC 3550: the estimator smooths the absolute change in relative
	// transit between consecutive packets.
	if s.haveLast {
		d := rel - s.lastRel
		if d < 0 {
			d = -d
		}
		s.jitter += jitterGain * (float64(d) - s.jitter)
	}
	s.lastRel = rel
	s.haveLast = true

	if !s.haveMin {
		s.haveMin = true
		s.windowMin = rel
		s.nextMin = rel
	} else {
		if rel < s.windowMin {
			s.windowMin = rel
		}
		if rel < s.nextMin {
			s.nextMin = rel
		}
	}

	// Re-arm: the minimum of the window just ended becomes the working
	// minimum, and the next window starts measuring afresh.
	if now-s.windowStart >= minWindow {
		s.windowMin = s.nextMin
		s.nextMin = rel
		s.windowStart = now
	}

	s.queueDelay = rel - s.windowMin
	s.received++
}

// observeLoss records a gap of n packets on this path, closing out any
// burst that was accumulating once delivery resumes.
func (s *pathStats) observeLoss(n uint32) {
	s.lost += uint64(n)
	s.runLen += int(n)
}

// observeDelivered closes an accumulating loss burst.
func (s *pathStats) observeDelivered() {
	if s.runLen == 0 {
		return
	}
	i := 0
	for i < len(burstBuckets) && s.runLen > burstBuckets[i] {
		i++
	}
	s.bursts[i]++
	s.runLen = 0
}

// percentile returns the given percentile of the transit samples, relative
// to the path's own baseline. Sorting a 200-element copy is only done when
// statistics are reported, never per packet.
func (s *pathStats) percentile(p float64) int32 {
	if s.filled == 0 {
		return 0
	}
	sorted := make([]int32, s.filled)
	copy(sorted, s.samples[:s.filled])
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	idx := int(p * float64(s.filled-1))
	return sorted[idx]
}

// spread reports the p95 transit above the path's own minimum. Absolute
// transit is not comparable between paths - each carries its own clock
// offset - but the distance from a path's own floor is, and it is what
// tail latency actually costs.
func (s *pathStats) spread() int32 {
	if s.filled == 0 {
		return 0
	}
	return s.percentile(0.95) - s.percentile(0)
}

// thin reports whether there are too few samples to draw conclusions from.
// protocol.md is explicit that ten packets tells you nothing about a loss
// rate, and that a path must never be promoted on thin statistics.
func (s *pathStats) thin() bool { return s.filled < 20 }
