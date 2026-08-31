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

// epochJump is the swing in relative transit taken as evidence that the
// peer restarted rather than that the network changed.
//
// Readings are held against a peer's clock, and a restart moves that clock
// back to zero, which shifts every reading by however long the peer had
// been up. The threshold sits far above any plausible network delay - a
// cellular carrier holding two seconds of packets in its own buffer is
// nowhere near it - so nothing the network does can be mistaken for a
// restart.
const epochJump = int32(30 * time.Second / time.Microsecond)

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

	// Loss over a recent window, kept alongside the lifetime totals.
	//
	// A lifetime figure is the wrong thing to lead an instrument with. An
	// incident that ended ten minutes ago goes on reading as a present
	// fault, and whoever is looking at it chases something that is
	// already over. Two windows are held so the reported figure does not
	// collapse to nothing the instant a window turns over.
	winStart time.Duration
	winRecv  uint64
	winLost  uint64
	prevRecv uint64
	prevLost uint64
}

// lossWindow is how much recent history the reported loss rate covers.
// Long enough to be a stable figure, short enough that a resolved problem
// stops being reported as a current one.
const lossWindow = 30 * time.Second

// rollLossWindow retires the current counting window when it is old enough.
func (s *pathStats) rollLossWindow(now time.Duration) {
	if now-s.winStart < lossWindow {
		return
	}
	s.prevRecv, s.prevLost = s.winRecv, s.winLost
	s.winRecv, s.winLost = 0, 0
	s.winStart = now
}

// recentLossPercent is loss across the current and previous windows, so it
// reflects roughly the last minute rather than all of history.
func (s *pathStats) recentLossPercent() float64 {
	recv, lost := s.winRecv+s.prevRecv, s.winLost+s.prevLost
	total := recv + lost
	if total == 0 {
		return 0
	}
	return float64(lost) / float64(total) * 100
}

// observeTransit folds one arrival into the statistics. transit is the raw
// mixed-clock reading; now is our own elapsed time, used only to age the
// rolling minimum window.
//
// It reports whether the peer appears to have restarted, in which case
// everything held against the old clock has been discarded and the
// caller's own per-path state - sequence numbers above all - is equally
// stale.
func (s *pathStats) observeTransit(transit uint32, now time.Duration) (peerRestarted bool) {
	if !s.haveBaseline {
		s.rebaseline(transit, now)
	}
	rel := int32(transit - s.baseline)

	if rel > epochJump || rel < -epochJump {
		s.rebaseline(transit, now)
		rel = 0
		peerRestarted = true
	}

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
	s.rollLossWindow(now)
	s.winRecv++
	return peerRestarted
}

// rebaseline starts the delay measurements over against a new clock,
// discarding everything derived from the old one. The cumulative delivery
// counters are left alone: they are not held against any clock, and the
// history they carry is still true.
func (s *pathStats) rebaseline(transit uint32, now time.Duration) {
	s.haveBaseline = true
	s.baseline = transit
	s.windowStart = now
	s.next, s.filled = 0, 0
	s.haveEWMA, s.haveLast, s.haveMin = false, false, false
	s.ewma, s.jitter = 0, 0
	s.queueDelay = 0
	s.winStart = now
}

// observeLoss records a gap of n packets on this path, closing out any
// burst that was accumulating once delivery resumes.
func (s *pathStats) observeLoss(n uint32) {
	s.lost += uint64(n)
	s.winLost += uint64(n)
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
