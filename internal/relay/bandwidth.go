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
	minStart  time.Duration
	minRTTMs  float64
	nextMinMs float64
	haveMin   bool

	// ceilingKbps is where a wall was actually observed, less the safety
	// margin - either queueing setting in, or (D-050) the peer reporting
	// real loss on a reading that never queued at all. Zero until one of
	// those has happened, and haveCeiling is what distinguishes "no ceiling
	// seen" from a genuine zero.
	ceilingKbps float64
	haveCeiling bool

	// queueing is whether the link was filling at the last reading, which
	// is what separates the onset of congestion from its continuation.
	queueing bool

	// onsetSince is when the current run of queueing began, or 0 when the
	// path is not queueing. candidateKbps is the send rate latched at that
	// moment - the last honest reading before the buffer started to fill.
	// Together they hold a suspected onset while it is confirmed against
	// BWOnsetDwell, so a single spike does not collapse the estimate.
	onsetSince    time.Duration
	candidateKbps float64

	// confirmedAt is when load last told us anything - either direction of
	// evidence. It is what ages, and the only thing that does.
	confirmedAt time.Duration
	everLoaded  bool

	// ceilingFloorMs is the path's minimum round trip at the moment the
	// ceiling was recorded, kept so a later reading can tell whether the
	// ceiling still describes the same link. See regimeChanged.
	ceilingFloorMs float64
}

// bwRegimeFactor is how far the round-trip floor has to move before the
// ceiling is treated as describing a different link.
//
// The floor is the round trip with nothing queued on it, so it is a property
// of the route rather than of the load: it moves when the route does. A
// handover to a different tower, a 5G-to-LTE fallback, or Starlink picking a
// different satellite all show up here, and none of them leave the old
// capacity figure meaning anything.
//
// Generous on purpose. This discards evidence, so it should fire on a route
// that has plainly changed and not on ordinary variation - and the cost of
// missing one is a stale estimate, which is the situation we were in anyway.
const bwRegimeFactor = 2.0

// regimeChanged reports whether the path underneath has changed enough that
// the recorded ceiling no longer describes it (D-047).
//
// The comment on the ageing constants above says an estimate ages in
// confidence but not in value, because "a link does not shrink because nobody
// used it". That is true of a fixed link and false of a vehicle. Driving out
// of a cell sector does not make the old number less certain, it makes it
// wrong, and holding 70% of a wrong number is worse than holding none:
// principle 3 says variable connectivity is the normal case here, and this is
// the one file that was assuming otherwise.
//
// So the ageing curve still handles a quiet link, and this handles a moved
// one. They answer different questions and both are needed.
func (b *bwEstimate) regimeChanged(rttFloorMs float64) bool {
	if !b.haveCeiling || b.ceilingFloorMs <= 0 || rttFloorMs <= 0 {
		return false
	}
	return rttFloorMs > b.ceilingFloorMs*bwRegimeFactor ||
		rttFloorMs*bwRegimeFactor < b.ceilingFloorMs
}

// forgetCeiling discards a ceiling that no longer describes the path.
func (b *bwEstimate) forgetCeiling() {
	b.ceilingKbps, b.haveCeiling, b.ceilingFloorMs = 0, false, 0
	b.queueing, b.onsetSince, b.candidateKbps = false, 0, 0
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
func (b *bwEstimate) observe(now time.Duration, rttMs, downQueueMs float64, tx peerView, c config.Config) {
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

	// A route that has plainly moved takes its capacity figure with it.
	// Checked before anything is concluded from this tick, so a reading
	// taken on the new route is never folded into the old estimate.
	if b.regimeChanged(b.minRTTMs) {
		b.forgetCeiling()
	}

	if now-b.winStart < bwRateWindow {
		return
	}
	elapsed := (now - b.winStart).Seconds()
	if elapsed > 0 {
		b.sendKbps = float64(b.bytes) * 8 / 1000 / elapsed
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

	up := b.outboundQueueMs(now, rttMs, downQueueMs, tx)

	if up >= float64(c.BWOnsetMs) {
		// The rate that matters is the one at the *moment* queueing began,
		// not every rate observed while it continues. Once a buffer is
		// filling, what is being pushed in is no longer what is coming out
		// the far side: a sender that keeps shoving 8 Mbps into a link that
		// collapsed to 2 would otherwise have that 8 recorded as the
		// ceiling, which is the opposite of the truth.
		if b.queueing {
			// Already in confirmed congestion. A lower rate that is still
			// queueing is direct evidence the wall moved in, and is trusted
			// at once - this is long past a transient blip. (D-023)
			//
			// Discounted by the loss the peer reports (D-049): what was sent
			// into a filling buffer is not what came out the other side, and
			// a link that is dropping most of its offered rate has not shown
			// a wall at the offered rate - it has shown one well below it.
			measured := b.deliveredKbps(tx) * bwSafety
			if measured < b.ceilingKbps {
				b.ceilingKbps = measured
			}
			return
		}

		// A fresh onset. Latch the delivered rate now, while it still means
		// something, but do not act on it until the queueing has held for
		// BWOnsetDwell. A single spike - one busy report interval - would
		// otherwise collapse a good estimate to whatever happened to be in
		// flight at that instant (D-023 revision, 2026-09-06).
		if b.onsetSince == 0 {
			b.onsetSince = now
			b.candidateKbps = b.deliveredKbps(tx) * bwSafety
		}
		if now-b.onsetSince >= c.BWOnsetDwell() {
			if !b.haveCeiling || b.candidateKbps < b.ceilingKbps {
				b.ceilingKbps = b.candidateKbps
				b.haveCeiling = true
				b.ceilingFloorMs = b.minRTTMs
			}
			b.queueing = true
			b.onsetSince = 0
		}
		return
	}
	// A clean reading breaks the streak: a suspected onset that did not
	// hold was a blip, and is forgotten.
	b.onsetSince = 0
	b.queueing = false
	delivered := b.deliveredKbps(tx)

	// Carrying this much with the link underneath still empty is evidence
	// the path can do at least this - it is allowed to lift a stale ceiling
	// that the path has visibly outgrown, but it never invents headroom
	// above what has actually flowed. Delivered, not sent (D-049): a path
	// losing packets without ever queueing - the D-046 case - must not lift
	// its own ceiling on traffic that was offered but did not arrive.
	if b.haveCeiling {
		if delivered > b.ceilingKbps {
			b.ceilingKbps = delivered
			b.ceilingFloorMs = b.minRTTMs
		}
		return
	}

	// No ceiling yet, and no queueing here to explain why (D-050 revision).
	// If the peer is reporting real loss, the loss is itself the wall - a
	// link dropping most of what it is given has shown a ceiling just as
	// surely as one that queues, and onset detection alone would never see
	// it: a dropped packet does not wait, it vanishes, so there is nothing
	// here for BWOnsetMs to ever measure. A clean reading with no loss
	// reported, or none in hand at all, stays "no opinion" - the ordinary
	// state of a link that has simply not failed yet, which must not read
	// as a ceiling of anything.
	if tx.valid && tx.loss > 0 {
		b.ceilingKbps = delivered * bwSafety
		b.haveCeiling = true
		b.ceilingFloorMs = b.minRTTMs
	}
}

// deliveredKbps is the send rate discounted by the loss the peer reports, or
// the raw send rate when no report is in hand.
//
// Without a report this is the send rate unmodified, which is the right
// fallback: an unreported path is not a lossy one, it is an unmeasured one,
// and assuming loss we cannot see would understate every quiet link's
// ceiling for no evidence at all.
func (b *bwEstimate) deliveredKbps(tx peerView) float64 {
	if !tx.valid || tx.loss <= 0 {
		return b.sendKbps
	}
	if tx.loss >= 100 {
		return 0
	}
	return b.sendKbps * (1 - tx.loss/100)
}

// outboundQueueMs is how much the link is queueing in our send direction.
//
// When the peer is reporting, this is simply what it measured - it is
// watching our packets arrive, so it can see our send direction directly
// and there is nothing to infer. That is the whole point of D-024.
//
// Without a report it falls back to the inference this estimator was built
// on: the round trip above its own floor, less the part of the rise we can
// already see belongs to the return direction. That works, and it is why
// the ceiling was measurable before path reports existed, but it is a
// difference of two noisy numbers and it degrades badly when both
// directions are busy at once.
func (b *bwEstimate) outboundQueueMs(now time.Duration, rttMs, downQueueMs float64, tx peerView) float64 {
	if tx.fresh(now) {
		return tx.queueMs
	}
	up := (rttMs - b.minRTTMs) - downQueueMs
	if up < 0 {
		return 0
	}
	return up
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
// A path with no observed wall - never seen to queue, and never reported to
// lose anything - returns 0. That is the honest answer: a link nobody has
// pushed hard enough to fail is not evidence that it is small. There used to
// be a configurable fallback here for a plan whose ceiling was known in
// advance; D-047 removed it as a knob nobody had set, doing a job a comment
// does better.
func (b *bwEstimate) limitKbps(now time.Duration, c config.Config) float64 {
	if !b.haveCeiling {
		return 0
	}
	return b.ceilingKbps * bwConfidence(now-b.confirmedAt)
}

// bwView is the estimate as the scheduler and the interface see it.
type bwView struct {
	sendKbps    float64
	ceilingKbps float64
	limitKbps   float64
	haveCeiling bool
	confirmedAt time.Duration
	everLoaded  bool
}

func (b *bwEstimate) view(now time.Duration, c config.Config) bwView {
	return bwView{
		sendKbps:    b.sendKbps,
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
