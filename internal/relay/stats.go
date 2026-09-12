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

	// The standing queue: the least reading across the last two short
	// buckets, above the same rolling minimum. queueDelay is one packet and
	// moves with every jitter spike; a queue that is really standing lifts
	// every reading in the window, so the least of them is the part that
	// would not drain if the next packet were the last. It is what the
	// cascade controller paces on (v0.2-design.md, section 5.4).
	standCur, standPrev int32
	haveStandCur        bool
	haveStandPrev       bool
	standStart          time.Duration
	standing            int32
	standingAt          time.Duration

	// Loss over the last second, in two half-second buckets, for the same
	// controller. The thirty-second window below is right for judging a
	// path and far too slow to pace on.
	shortStart           time.Duration
	shortRecv, shortLost uint64
	shortPrevRecv        uint64
	shortPrevLost        uint64
	shortBytes           uint64
	shortPrevBytes       uint64
	shortPrevValid       bool

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

	// Bursts closed within those same windows. The count is what turns a
	// loss rate into a burst ratio: the scoring model weighs clustered
	// loss far more heavily than scattered loss, and cannot tell them
	// apart from a rate alone.
	winBursts  uint64
	prevBursts uint64
}

// standBucket is the width of one standing-queue bucket. Two of them make
// the window, so a reading is at most ~100 ms old - a couple of report
// intervals at the cascade cadence, and long enough to span several packets
// on anything carrying enough traffic to be worth pacing.
const standBucket = 50 * time.Millisecond

// standingStale is how long the last standing-queue reading is believed once
// nothing more has arrived. Silence is not evidence the queue drained.
const standingStale = time.Second

// shortLossBucket is half the short loss window.
const shortLossBucket = 500 * time.Millisecond

// observeStanding folds one relative transit reading into the standing
// queue window.
func (s *pathStats) observeStanding(rel int32, now time.Duration) {
	if now-s.standStart >= standBucket {
		// Turn the bucket over. A gap longer than two buckets leaves nothing
		// from before it worth keeping.
		s.standPrev, s.haveStandPrev = s.standCur, s.haveStandCur && now-s.standStart < 2*standBucket
		s.haveStandCur = false
		s.standStart = now
	}
	if !s.haveStandCur || rel < s.standCur {
		s.standCur, s.haveStandCur = rel, true
	}
	least := s.standCur
	if s.haveStandPrev && s.standPrev < least {
		least = s.standPrev
	}
	s.standing = least - s.windowMin
	if s.standing < 0 {
		s.standing = 0
	}
	s.standingAt = now
}

// standingQueue is the standing queue in microseconds, or zero once the
// reading is too old to say anything.
func (s *pathStats) standingQueue(now time.Duration) int32 {
	if s.standingAt == 0 || now-s.standingAt > standingStale {
		return 0
	}
	return s.standing
}

// rollShortLoss turns the short loss buckets over.
func (s *pathStats) rollShortLoss(now time.Duration) {
	if now-s.shortStart < shortLossBucket {
		return
	}
	if now-s.shortStart < 2*shortLossBucket {
		s.shortPrevRecv, s.shortPrevLost, s.shortPrevBytes = s.shortRecv, s.shortLost, s.shortBytes
		s.shortPrevValid = true
	} else {
		s.shortPrevRecv, s.shortPrevLost, s.shortPrevBytes = 0, 0, 0
		s.shortPrevValid = false
	}
	s.shortRecv, s.shortLost, s.shortBytes = 0, 0, 0
	s.shortStart = now
}

// shortLossPercent is loss over roughly the last second.
func (s *pathStats) shortLossPercent(now time.Duration) float64 {
	if now-s.shortStart >= 2*shortLossBucket {
		return 0 // nothing has arrived for a second; no fresh evidence either way
	}
	recv, lost := s.shortRecv+s.shortPrevRecv, s.shortLost+s.shortPrevLost
	if recv+lost == 0 {
		return 0
	}
	return float64(lost) / float64(recv+lost) * 100
}

// noteBytes counts the wire bytes of an arrival toward the short receive
// rate. Called after observeTransit, which turns the buckets over.
func (s *pathStats) noteBytes(n int) { s.shortBytes += uint64(n) }

// shortRxKbps is what arrived on the path over roughly the last second.
func (s *pathStats) shortRxKbps(now time.Duration) float64 {
	cur := now - s.shortStart
	if cur >= 2*shortLossBucket || cur < 0 {
		return 0
	}
	bytes, span := s.shortBytes, cur
	if s.shortPrevValid {
		bytes += s.shortPrevBytes
		span += shortLossBucket
	}
	if span < 100*time.Millisecond {
		span = 100 * time.Millisecond // a bucket just turned over is not a rate
	}
	return float64(bytes) * 8 / 1000 / span.Seconds()
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
	s.prevBursts = s.winBursts
	s.winRecv, s.winLost, s.winBursts = 0, 0, 0
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
	s.observeStanding(rel, now)
	s.received++
	s.rollLossWindow(now)
	s.winRecv++
	s.rollShortLoss(now)
	s.shortRecv++
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
	s.haveStandCur, s.haveStandPrev = false, false
	s.standing, s.standingAt, s.standStart = 0, 0, now
}

// observeLoss records a gap of n packets on this path, closing out any
// burst that was accumulating once delivery resumes.
func (s *pathStats) observeLoss(n uint32) {
	s.lost += uint64(n)
	s.winLost += uint64(n)
	s.shortLost += uint64(n)
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
	s.winBursts++
	s.runLen = 0
}

// recentBurstRatio reports how clustered the recent loss was, as the mean
// observed burst length against the mean that random loss at the same rate
// would have produced. It returns 1 when loss is scattered exactly as
// chance would scatter it, and climbs as loss arrives in runs.
//
// Random loss at probability p produces bursts averaging 1/(1-p) packets,
// so dividing by that is the same as multiplying by (1-p).
func (s *pathStats) recentBurstRatio() float64 {
	lost := s.winLost + s.prevLost
	bursts := s.winBursts + s.prevBursts
	if lost == 0 || bursts == 0 {
		return 1
	}
	total := lost + s.winRecv + s.prevRecv
	if total == 0 {
		return 1
	}
	p := float64(lost) / float64(total)
	ratio := (float64(lost) / float64(bursts)) * (1 - p)
	if ratio < 1 {
		return 1
	}
	return ratio
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
