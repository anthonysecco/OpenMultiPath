package relay

import (
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
)

// Reactive bandwidth ceiling, D-023 and step 6b of scope-v1.md.
//
// The scheduler scores paths on voice quality - loss, jitter, queue delay -
// and has no idea how much a path can carry. That gap has a specific and
// already-observed failure: a metered link sitting idle carries nothing but
// probes, so it queues nothing and loses nothing, and reads as the
// healthiest path on the box right up until something real is steered onto
// it. Picking it as a duplication target is then how a 512k standby link
// produces eight thousand lost packets on one file copy.
//
// The fix is not to measure capacity actively. Packet trains and pair
// dispersion are unreliable on a link whose capacity moves with the weather,
// and on a metered link the probe spends exactly the resource it is trying
// to count. Instead the estimate is taken from traffic that was going to be
// sent anyway: watch how much is going onto a path, watch whether the link
// underneath has started to queue, and let the two together say where the
// wall is.
//
// The signal is deliberately the *send* direction, because that is the
// direction the scheduler decides. Queue delay from pathStats is the
// receive direction only - it is built from arrival timestamps - so it
// cannot answer the question on its own. What can is the round trip against
// its own floor, less the part of that rise we can already see belongs to
// the return direction. One subtraction, and it keeps a large download
// arriving on a path from being misread as that path's uplink filling up.

const (
	// bwRateWindow is how long one send-rate sample covers. Short enough to
	// catch the moment a transfer starts pushing, long enough that a single
	// video frame's worth of packets is not read as a burst to the moon.
	bwRateWindow = 500 * time.Millisecond

	// bwMinWindow re-arms the round-trip floor, for the same reason
	// stats.go re-arms the transit minimum: a floor that is never renewed
	// belongs to a link that no longer exists, and a path whose base delay
	// really did move - a handover onto a farther cell - would read as
	// permanently congested.
	//
	// It is far longer than the ten seconds stats.go uses, and that
	// difference is the point. Ten seconds is right for "is this path
	// degraded right now", which is a question about the present. Capacity
	// is a question about the link, and a standing queue that lasts a
	// minute is exactly the evidence being looked for - absorbing it into
	// the baseline would turn a badly congested link into one that reads as
	// clean at whatever rate is being forced into it.
	bwMinWindow = 5 * time.Minute

	// bwSafety is the margin held back from a rate that was observed to
	// start queueing. The rate at onset is where the link began to hurt,
	// not where it is comfortable.
	bwSafety = 0.85

	// An estimate ages in confidence, not in value. The number measured
	// during a burst an hour ago is still the best number available - a link
	// does not shrink because nobody used it - so it is never quietly
	// rewritten. What changes is how much of it is leaned on: full weight
	// while fresh, sliding down to bwStaleFloor once nothing has confirmed
	// it for bwStaleAfter, and no further. Discarding it entirely would be
	// worse than trusting it, because the alternative is knowing nothing.
	bwFreshFor   = 60 * time.Second
	bwStaleAfter = 15 * time.Minute
	bwStaleFloor = 0.7
)

// bwEstimate is one path's view of how much it can carry. It lives under
// the session lock beside the MTU search, which it deliberately resembles:
// both are slow searches for a ceiling, driven by traffic, revised
// downwards on evidence and upwards only on better evidence.
type bwEstimate struct {
	started bool

	// Send-rate accounting. bytes accumulates at transmit and is turned
	// into a rate once per window.
	bytes     uint64
	winStart  time.Duration
	sendKbps  float64
	peakKbps  float64
	minStart  time.Duration
	minRTTMs  float64
	nextMinMs float64
	haveMin   bool

	// provenKbps is the highest rate this path has carried with the link
	// underneath still empty. It is a floor on capacity, not a ceiling: it
	// says the path can do at least this, and nothing at all about what
	// happens above it.
	provenKbps float64

	// ceilingKbps is where queueing was actually observed to set in, less
	// the safety margin. Zero until that has happened, and haveCeiling is
	// what distinguishes "no ceiling seen" from a genuine zero.
	ceilingKbps float64
	haveCeiling bool

	// queueing is whether the link was filling at the last reading, which
	// is what separates the onset of congestion from its continuation.
	queueing bool

	// confirmedAt is when load last told us anything - either direction of
	// evidence. It is what ages, and the only thing that does.
	confirmedAt time.Duration
	everLoaded  bool
}

// noteSent accounts for one packet put onto this path, in wire bytes.
func (b *bwEstimate) noteSent(wireBytes int) {
	b.bytes += uint64(wireBytes)
}

// observe folds one evaluation tick into the estimate.
//
// rttMs is the path's most recent round trip and downQueueMs the queue
// delay already measured in the receive direction; the difference between
// the round trip's rise and that is what this end is doing to the link.
func (b *bwEstimate) observe(now time.Duration, rttMs, downQueueMs float64, c config.Config) {
	if !b.started {
		// Start the windows here rather than at zero. A path registered at
		// boot and first sampled a minute later would otherwise divide a
		// handful of probe bytes by a minute, or worse, by nothing.
		b.started = true
		b.winStart, b.minStart = now, now
		b.bytes = 0
		return
	}

	b.trackFloor(now, rttMs)

	if now-b.winStart < bwRateWindow {
		return
	}
	elapsed := (now - b.winStart).Seconds()
	if elapsed > 0 {
		b.sendKbps = float64(b.bytes) * 8 / 1000 / elapsed
		if b.sendKbps > b.peakKbps {
			b.peakKbps = b.sendKbps
		}
	}
	b.bytes, b.winStart = 0, now

	// Below the floor there is not enough traffic on the path for its
	// behaviour to mean anything. An idle path is not evidence of a small
	// link; it is evidence of nothing, and reading it as either is the
	// mistake this whole file exists to avoid.
	if !b.haveMin || rttMs <= 0 || b.sendKbps < float64(c.BWMinLoadKbps) {
		return
	}
	b.everLoaded = true
	b.confirmedAt = now

	up := (rttMs - b.minRTTMs) - downQueueMs
	if up < 0 {
		up = 0
	}

	if up >= float64(c.BWOnsetMs) {
		// The rate that matters is the one at the *moment* queueing began,
		// not every rate observed while it continues. Once a buffer is
		// filling, what is being pushed in is no longer what is coming out
		// the far side: a sender that keeps shoving 8 Mbps into a link that
		// collapsed to 2 would otherwise have that 8 recorded as the
		// ceiling, which is the opposite of the truth.
		//
		// So the estimate is taken on the transition, and afterwards may
		// only ratchet down. A lower rate that is still queueing is direct
		// evidence the wall moved in.
		measured := b.sendKbps * bwSafety
		switch {
		case !b.queueing, measured < b.ceilingKbps:
			b.ceilingKbps = measured
			b.haveCeiling = true
		}
		b.queueing = true
		if b.provenKbps > b.ceilingKbps {
			b.provenKbps = b.ceilingKbps
		}
		return
	}
	b.queueing = false

	// Carrying this much with the link underneath still empty proves the
	// path can take at least this much. That is a floor, so it is recorded
	// as one, and it is allowed to lift a stale ceiling that the path has
	// visibly outgrown - but it never invents headroom above what has
	// actually flowed.
	if b.sendKbps > b.provenKbps {
		b.provenKbps = b.sendKbps
	}
	if b.haveCeiling && b.sendKbps > b.ceilingKbps {
		b.ceilingKbps = b.sendKbps
	}
}

// trackFloor keeps the rolling minimum round trip, re-armed on the same
// two-window scheme as the transit minimum in stats.go.
func (b *bwEstimate) trackFloor(now time.Duration, rttMs float64) {
	if rttMs <= 0 {
		return
	}
	if !b.haveMin {
		b.haveMin, b.minRTTMs, b.nextMinMs = true, rttMs, rttMs
		b.minStart = now
		return
	}
	if rttMs < b.minRTTMs {
		b.minRTTMs = rttMs
	}
	if rttMs < b.nextMinMs {
		b.nextMinMs = rttMs
	}
	if now-b.minStart >= bwMinWindow {
		b.minRTTMs, b.nextMinMs, b.minStart = b.nextMinMs, rttMs, now
	}
}

// confidence is how much of the recorded ceiling is currently leaned on.
// Full weight while fresh, sliding to bwStaleFloor as the estimate goes
// unconfirmed, and never below it.
func bwConfidence(age time.Duration) float64 {
	switch {
	case age <= bwFreshFor:
		return 1
	case age >= bwStaleAfter:
		return bwStaleFloor
	}
	frac := float64(age-bwFreshFor) / float64(bwStaleAfter-bwFreshFor)
	return 1 - frac*(1-bwStaleFloor)
}

// limitKbps is what the scheduler may assume this path can carry, or 0 for
// "no opinion" - which every caller must read as permission, not refusal.
//
// A path with no observed onset returns the configured fallback, which
// defaults to 0. That is the honest answer: never having seen a path queue
// is not evidence that it is small.
func (b *bwEstimate) limitKbps(now time.Duration, c config.Config) float64 {
	if !b.haveCeiling {
		return float64(c.BWFallbackKbps)
	}
	return b.ceilingKbps * bwConfidence(now-b.confirmedAt)
}

// bwView is the estimate as the scheduler and the interface see it.
type bwView struct {
	sendKbps    float64
	peakKbps    float64
	provenKbps  float64
	ceilingKbps float64
	limitKbps   float64
	haveCeiling bool
	confirmedAt time.Duration
	everLoaded  bool
}

func (b *bwEstimate) view(now time.Duration, c config.Config) bwView {
	return bwView{
		sendKbps:    b.sendKbps,
		peakKbps:    b.peakKbps,
		provenKbps:  b.provenKbps,
		ceilingKbps: b.ceilingKbps,
		limitKbps:   b.limitKbps(now, c),
		haveCeiling: b.haveCeiling,
		confirmedAt: b.confirmedAt,
		everLoaded:  b.everLoaded,
	}
}

// canCarry reports whether this path may be offered loadKbps on top of
// whatever it is already doing, with the configured headroom on top.
//
// A path with no opinion always may. This is the soft gate of D-023: it
// exists to keep a saturating transfer off a link that has already shown it
// cannot take one, not to make a path ineligible. Every caller keeps its
// own fallback for the case where the gate would leave nothing at all.
func (v bwView) canCarry(loadKbps float64, c config.Config) bool {
	if v.limitKbps <= 0 {
		return true
	}
	needed := (v.sendKbps + loadKbps) * (1 + float64(c.BWHeadroomPercent)/100)
	return needed <= v.limitKbps
}

// bwPreferFactor is how much more capacity a path needs before it displaces
// an equally-scoring primary. A factor rather than a margin, because these
// links differ by orders of magnitude rather than by percentages: the case
// this exists for is 512 kbps against tens of megabits, not 8 Mbps against
// 9. Set high enough that ordinary variation in the estimate never triggers
// a handover, since the estimate tracks demand as much as capacity and a
// tighter rule would chase it.
const bwPreferFactor = 2.0
