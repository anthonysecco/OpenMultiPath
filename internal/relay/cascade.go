package relay

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
	"github.com/anthonysecco/OpenMultiPath/internal/usage"
)

// The cascade is v0.2's bulk scheduler (v0.2-design.md, section 5).
//
// v0.1 placed bulk per flow: each download was hashed onto one path of a
// load-balancing set, so a single flow never exceeded a single link, and the
// call's path was protected by a gate that dropped all bulk the moment that
// path queued. The cascade places bulk per packet instead:
//
//   - it fills the slowest usable path first, where latency costs a download
//     nothing, and spills onto the next faster path only once that one is
//     full, and so on down to the path carrying the call, which is always
//     last;
//   - how much each path takes is set by a controller per path, reading the
//     standing queue and short-window loss the far end reports on our send
//     direction, and cutting at once and growing back only after a clean run;
//   - the far end puts each flow back in order (reseq.go).
//
// Real-time traffic on a path changes only where that path sits in the fill
// order: last. It never throttles or holds bulk back. The call's path is
// filled by the same controller as every other path, and past every path's
// allowance bulk overflows onto whichever path is least queued rather than
// being dropped here. That is the owner's rule (2026-09-12), and it replaces
// admission control's gate outright in cascade mode (S7); flow mode keeps
// the gate, being v0.1 exactly.
//
// It is only ever active when every one of these holds: the operator has not
// switched it off (bulk_scheduler), the peer can resequence (wire version 3),
// classes are real (above WireGuard), and the scheduler is not spraying
// blind. Otherwise bulk is placed exactly as v0.1 placed it. Spreading a flow
// into a receiver that cannot reorder it is how D-044's first live test fell
// to 4 Mbps.

// cascadeMember is one path the cascade may put bulk on, in fill order.
type cascadeMember struct {
	id        uint8
	protected bool    // carries real-time or transactional traffic; always last
	capKbps   float64 // how much bulk it may take; 0 is unlimited
	sentKbps  float64 // bulk it carried over the last evaluation
}

// capDemand is what the controller knows about the demand on one path over
// the last evaluation.
type capDemand struct {
	sentKbps float64
	// exhausted means at least one bulk packet found this path's allowance
	// spent and went on to a later path, or was dropped. That is direct
	// evidence the path could have carried more if its cap allowed.
	exhausted bool
}

// capCtl is the controller for one path's bulk allowance.
type capCtl struct {
	capKbps    float64 // 0 is unlimited
	clean      int
	lastCut    time.Duration
	haveCut    bool
	queueAtCut float64 // the standing queue the last cut was made against
	cutFrom    float64 // the delivered rate the last cut was made from
	lastQueue  float64 // the standing queue at the previous evaluation
	haveQueue  bool
	overFor    int // consecutive evaluations over the target or loss line

	// blameless marks an allowance cut while almost no bulk was on the
	// path: the queue was someone else's - a download still classed as
	// transactional, a page load - and bulk was only kept off while it
	// stood. Once the path is clean it goes back to uncapped rather than
	// crawling up from the floor, because nothing ever showed bulk was the
	// problem.
	blameless  bool
	lastMember time.Duration

	// The best delivered rate over the current and previous peak windows.
	// See cascadePeakHeadroom.
	peakCur, peakPrev float64
	peakAt            time.Duration
}

// The controller's gains. Deliberately constants rather than settings: every
// one is a guess, and the road will say which of them needs to move before a
// knob for it is worth the space in the interface.
const (
	// cascadeMinCapKbps is the floor a cut stops at. An allowance only sets
	// how much of the bulk a path takes before the rest spills on; it never
	// stops bulk, so a low floor costs nothing but a little spill.
	cascadeMinCapKbps = 64

	// cascadeGrowth is the per-evaluation growth once a path has been clean
	// for long enough - about 1.6x a second at the default cadence - and
	// cascadeFastGrowth the growth while the allowance is still under half
	// the rate the last cut was made from. The lab took ten seconds to climb
	// back from a deep cut at the slow rate, for capacity it had already
	// shown it had.
	cascadeGrowth     = 1.10
	cascadeFastGrowth = 1.30

	// cascadeDemandShare is how close to its cap a path must be running for
	// the cap to grow. An allowance nobody is pushing against is not
	// evidence of headroom.
	cascadeDemandShare = 0.9

	// cascadeUnlimitedKbps is where a growing cap stops being a cap.
	cascadeUnlimitedKbps = 10_000_000

	// cascadeTrimQueueMs is the standing queue above which a still-rising
	// queue trims a path's allowance to what it is delivering. Low on
	// purpose: a BBR sender keeps a bottleneck's queue to a few
	// milliseconds, and a trim that waited for half the target never fired
	// under one, leaving the first path's allowance above its link and
	// nothing ever spilling to the second.
	cascadeTrimQueueMs = 5

	// cascadePeakHeadroom bounds a path's allowance, once it has been seen
	// to congest, to this much above the best it has actually delivered over
	// the last one to two seconds (cascadePeakWindow).
	//
	// This is what lets a sender that keeps queues short aggregate at all.
	// BBR paces at the rate it has seen delivered and probes a quarter above
	// it now and then; if the first path's allowance floats above what that
	// link can carry, the probe's extra just queues there briefly and
	// nothing ever spills, so the second link stays idle forever. Held to a
	// tenth above what arrives, the probe's extra spills onto the next path,
	// arrives, and the sender's next estimate is the two links together. The
	// lab measured exactly that failure before this: a BBR flow at one
	// link's rate with a second idle beside it.
	//
	// Below the probe gain on purpose, and loose enough that a path with
	// room grows its allowance a tenth a second as it proves it.
	cascadePeakHeadroom = 1.10
	cascadePeakWindow   = time.Second

	// cascadeConfirmIntervals is how many evaluations running a path must
	// read over its queue target or loss line before it is cut. One report is
	// one reading, and on Starlink
	// one reading is noise: idle, the send direction read 8.6 ms of standing
	// queue at the median, 24.6 at p90 and 64.7 at worst, against a 40 ms
	// target. D-023 needed a dwell for the same link and the same reason.
	cascadeConfirmIntervals = 2

	// cascadeLossCut is the cut for loss with no queue behind it.
	cascadeLossCut = 0.8

	// cascadeCutSpacing is the least time between two cuts on one path. A
	// cut takes a round trip and a report to show up in what the far end
	// measures; cutting again before then cuts for the same queue twice.
	cascadeCutSpacing = 500 * time.Millisecond

	// cascadeDrainGrace is how long a queue that is already shrinking after
	// a cut is left to drain before being cut for again. A deep buffer
	// filled by a TCP flow's overshoot takes seconds to empty even at a rate
	// well under the link's; cutting on every report while it does ratchets
	// the allowance to the floor for a queue that was already going away.
	// Found in the network namespace lab, where it held a 20 Mbit link to
	// 12 Mbit.
	cascadeDrainGrace = 2 * time.Second

	// cascadeStaleReports is how many cascade report intervals a report may
	// be late before the controller stops acting on it and holds.
	cascadeStaleReports = 3

	// cascadeSwapTicks is how many evaluations running a slower path must
	// have been slower before it overtakes the one ahead.
	cascadeSwapTicks = 5

	// cascadeForgetAfter is how long a path may be out of the cascade before
	// its controller starts again from unlimited. A link that has been gone
	// that long has probably moved cell, and the old cap belongs to the old
	// one.
	cascadeForgetAfter = 30 * time.Second
)

// cascadeInactive says why the cascade is not running, or "" when it may.
func (s *scheduler) cascadeInactive(d *decision, c config.Config) string {
	switch {
	case c.BulkScheduler != config.BulkCascade:
		return "bulk_scheduler is flow"
	case !s.classifying.Load():
		return "not classifying, so bulk cannot be told from a call"
	case s.peerResequences == nil || !s.peerResequences():
		return "the peer cannot resequence (wire version below 3)"
	case d.blind:
		return "no usable path"
	case !d.havePrimary:
		return "no primary chosen yet"
	}
	return ""
}

// healthyForCascade is who may take spread bulk: not red, not down, and
// delivering - quality over the reported send direction and not flapping
// (D-046).
//
// Not "stable", which v0.1's spread required (D-044). There it kept a
// radio-lossy link out of a hash that would hand it half the flows for
// their whole lives. Here the controller cuts a lossy link's allowance on
// its own, and requiring stable excludes exactly the path the cascade is
// filling: a queue our own bulk built is enough for the state machine to
// call a path unstable, and the lab run that found this lost its whole
// second link to it.
func healthyForCascade(now time.Duration, sc scored, c config.Config) bool {
	if sc.m.budget.Band == usage.Red || sc.mach.state == stateDown {
		return false
	}
	return deliveringForSpread(now, sc, c)
}

// baseDelayMs is a path's delay with nothing queued on it: half its round-
// trip floor, or half the live round trip before a floor exists. What the
// cascade orders and gates on.
//
// Not the scoring delay, which adds the reported p95 tail. That tail holds
// whatever queue our own bulk built, for as long as the last two hundred
// samples remember it, so ordering on it would move bulk off a path because
// bulk was on it - the cascade chasing its own queue - and the delta gate
// would drop a link for minutes after one burst. Queueing is the
// controller's to manage; the order is about the links.
func baseDelayMs(m pathMetric) float64 {
	if m.rttFloorMs > 0 {
		return m.rttFloorMs / 2
	}
	return m.rttMs / 2
}

// buildCascade decides this evaluation's cascade and publishes it on d.
func (s *scheduler) buildCascade(now time.Duration, d *decision, c config.Config, eligible []scored) {
	if why := s.cascadeInactive(d, c); why != "" {
		d.cascadeWhy = why
		s.setCascadeActive(false, why)
		s.cascadeOrder = nil
		s.swapFor = nil
		s.caps = nil
		return
	}

	byID := make(map[uint8]scored, len(eligible))
	for _, sc := range eligible {
		byID[sc.m.id] = sc
	}
	base := func(id uint8) float64 { return baseDelayMs(byID[id].m) }
	protected := make(map[uint8]bool, len(d.tx))
	for _, id := range d.tx {
		protected[id] = true
	}

	// The delta gate: a path so far behind the call's path that its packets
	// would arrive after the far end had given up waiting for them is worth
	// nothing to a spread flow.
	primaryDelay := base(d.primary)
	maxBehind := float64(c.ResequencerMaxHoldMs - c.ResequencerHoldMarginMs)
	inReach := func(sc scored) bool { return baseDelayMs(sc.m)-primaryDelay <= maxBehind }

	// D-045's size gate, with the bar taken over every healthy path, the
	// call's included. v0.1 left the call's path out of the bar because bulk
	// was kept off it; the cascade fills it last, so it is a peer like any
	// other. Leaving it out compared the vehicle's 3 Mbit Starlink tier with
	// nothing but itself, and the cascade filled that first while a 55 Mbit
	// AT&T link waited behind it.
	var bestKbps float64
	for _, sc := range eligible {
		if healthyForCascade(now, sc, c) && sc.m.bw.limitKbps > bestKbps {
			bestKbps = sc.m.bw.limitKbps
		}
	}
	var members []scored
	for _, sc := range eligible {
		if protected[sc.m.id] || !healthyForCascade(now, sc, c) ||
			undersizedForSpread(sc.m.bw.limitKbps, bestKbps, c) || !inReach(sc) {
			continue
		}
		members = append(members, sc)
	}
	// No forest-canopy fallback (D-033). Placed per flow, a flapping link was a
	// fine home for traffic that can wait: each flow took what got through.
	// Spread per packet, a flapping link stalls every flow it touches at the
	// far end, waiting for bursts of packets that never arrive. On the vehicle
	// a flapping Starlink put back first in line this way took a single upload
	// from 68 Mbit to 0.1. Unstable links that are not flapping are already
	// members; a flapping one waits until it stops.

	order := s.orderCascade(c, members)

	if s.caps == nil {
		s.caps = make(map[uint8]*capCtl)
	}
	sent := s.bulkRates(now)
	exhausted := s.exhaustedSince()

	d.cascade = d.cascade[:0]
	d.cascadeIDs = d.cascadeIDs[:0]
	add := func(id uint8, prot bool) {
		ctl := s.caps[id]
		if ctl == nil || now-ctl.lastMember > cascadeForgetAfter {
			ctl = &capCtl{}
			s.caps[id] = ctl
		}
		ctl.lastMember = now
		sc := byID[id]
		before := ctl.capKbps
		ctl.update(now, sc.m, capDemand{sentKbps: sent[id], exhausted: exhausted[id]}, c)
		s.logCap(id, prot, before, ctl.capKbps)
		d.cascade = append(d.cascade, cascadeMember{id: id, protected: prot, capKbps: ctl.capKbps, sentKbps: sent[id]})
		d.cascadeIDs = append(d.cascadeIDs, id)
	}
	for _, id := range order {
		add(id, false)
	}
	for _, id := range d.tx {
		if _, ok := byID[id]; ok {
			add(id, true)
		}
	}

	// Where bulk goes once every allowance is spent: the first path in fill
	// order. Past its allowance a download queues where it would have gone
	// first anyway, and the call's path takes only its own share - unless it
	// is the only path, when it takes everything.
	d.overflowIdx = 0

	d.cascadeOn = len(d.cascade) > 0
	if !d.cascadeOn {
		d.cascadeWhy = "no path to place bulk on"
	}
	s.setCascadeActive(d.cascadeOn, d.cascadeWhy)
}

// orderCascade sorts the unprotected members slowest first, holding the
// previous order against small differences (v0.2-design.md, section 5.2).
func (s *scheduler) orderCascade(c config.Config, members []scored) []uint8 {
	delay := make(map[uint8]float64, len(members))
	for _, sc := range members {
		delay[sc.m.id] = baseDelayMs(sc.m)
	}

	// Keep the previous order for whoever is still a member, and slot newcomers
	// in where their delay puts them.
	order := make([]uint8, 0, len(members))
	for _, id := range s.cascadeOrder {
		if _, ok := delay[id]; ok {
			order = append(order, id)
		}
	}
	placed := make(map[uint8]bool, len(order))
	for _, id := range order {
		placed[id] = true
	}
	newcomers := make([]uint8, 0)
	for _, sc := range members {
		if !placed[sc.m.id] {
			newcomers = append(newcomers, sc.m.id)
		}
	}
	sort.Slice(newcomers, func(i, j int) bool { return delay[newcomers[i]] > delay[newcomers[j]] })
	for _, id := range newcomers {
		at := len(order)
		for i, other := range order {
			if delay[id] > delay[other] {
				at = i
				break
			}
		}
		order = append(order, 0)
		copy(order[at+1:], order[at:])
		order[at] = id
	}

	// One pass of hysteresis-guarded swaps. Two adjacent members trade places
	// only once the one behind has been the slower by more than the margin for
	// several evaluations running.
	hyst := float64(c.CascadeOrderHysteresisMs)
	swaps := make(map[[2]uint8]int)
	for i := 0; i+1 < len(order); i++ {
		a, b := order[i], order[i+1]
		if delay[b]-delay[a] <= hyst {
			continue
		}
		key := [2]uint8{a, b}
		n := s.swapFor[key] + 1
		if n < cascadeSwapTicks {
			swaps[key] = n
			continue
		}
		order[i], order[i+1] = b, a
		log.Printf("cascade: %s is now filled before %s (%.0f ms against %.0f ms out)",
			s.pathName(b), s.pathName(a), delay[b], delay[a])
		i++ // the pair just swapped is settled for this evaluation
	}
	s.swapFor = swaps

	s.cascadeOrder = append(s.cascadeOrder[:0], order...)
	return order
}

// bulkRates reads how much bulk each path carried since the last evaluation,
// in kbps, from the counters the data path keeps.
func (s *scheduler) bulkRates(now time.Duration) map[uint8]float64 {
	out := make(map[uint8]float64)
	elapsed := now - s.lastBulkAt
	first := s.lastBulkAt == 0
	s.lastBulkAt = now
	for i := range s.bulkBytes {
		total := s.bulkBytes[i].Load()
		delta := total - s.lastBulkBytes[i]
		s.lastBulkBytes[i] = total
		if first || elapsed <= 0 || delta == 0 {
			continue
		}
		out[uint8(i)] = float64(delta) * 8 / 1000 / elapsed.Seconds()
	}
	return out
}

// exhaustedSince reports which paths turned a bulk packet away for want of
// allowance since the last evaluation.
func (s *scheduler) exhaustedSince() map[uint8]bool {
	out := make(map[uint8]bool)
	for i := range s.exhaustedCount {
		n := s.exhaustedCount[i].Load()
		if n != s.lastExhausted[i] {
			out[uint8(i)] = true
		}
		s.lastExhausted[i] = n
	}
	return out
}

// update advances one path's controller by an evaluation
// (v0.2-design.md, section 5.4).
//
// Every path runs the same controller against the same target, the call's path
// included: real-time on a path decides its place in the order, not how much
// bulk it may carry.
func (ctl *capCtl) update(now time.Duration, m pathMetric, demand capDemand, c config.Config) {
	sentKbps := demand.sentKbps
	delivered := bulkDeliveredKbps(m, sentKbps)
	// No evidence at all: do not throttle. The same answer admission control
	// gave, and for the same reason - the failure of a pacing mechanism with
	// nothing to go on should be traffic flowing.
	if m.txAge < 0 || !m.haveTx {
		ctl.capKbps, ctl.clean = 0, 0
		return
	}
	// Evidence gone quiet: hold. Not growing on a path nobody can currently
	// see is the cautious half; not cutting on silence is the other, since
	// the path machine is what judges a path that has stopped answering.
	if m.txAge > cascadeStaleReports*c.CascadeReportInterval() {
		return
	}
	// Bounded by what has actually been delivered, whatever the rules below
	// decide - but only on fresh evidence, like everything else here.
	defer ctl.boundByPeak(now, delivered)

	target := float64(c.CascadeQueueTargetMs)
	need := c.CascadeRecoverIntervals
	queue, loss := m.txStandingMs, m.txShortLoss
	// A path carrying next to nothing is measured on next to nothing: its
	// "standing queue" is a single report's worth of samples, and its loss a
	// handful of packets. Read as congestion, that cut idle links to the floor
	// on the real vehicle, where they then never carried enough bulk to be
	// measured properly - both links at 64 kbps and a download at a tenth of
	// what flow placement managed. The bandwidth estimator ignores a path
	// under the same load for the same reason.
	if m.bw.sendKbps < float64(c.BWMinLoadKbps) {
		queue, loss = 0, 0
	}
	queued := queue > target
	lossy := loss >= float64(c.CascadeLossPercent)
	rising := ctl.haveQueue && queue > ctl.lastQueue
	ctl.lastQueue, ctl.haveQueue = queue, true

	if queued || lossy {
		ctl.clean = 0
		ctl.overFor++
		if ctl.overFor < cascadeConfirmIntervals {
			return
		}
		if ctl.haveCut {
			since := now - ctl.lastCut
			if since < cascadeCutSpacing {
				return
			}
			// Already draining from the last cut: give it time.
			if queued && !lossy && queue < ctl.queueAtCut && since < cascadeDrainGrace {
				return
			}
		}
		f := cascadeLossCut
		if queued {
			f = clampFloat(1-0.5*(queue-target)/target, 0.5, 0.9)
		}
		// Cut from what actually arrived, not what was offered (D-050): a
		// link losing a third of its traffic has not got the capacity it was
		// handed.
		base := delivered
		if ctl.capKbps > 0 && ctl.capKbps < base {
			base = ctl.capKbps
		}
		// Seeded, the first time, from the bandwidth estimate where it has
		// one and it is lower. Its only job here (section 5.4).
		if ctl.capKbps == 0 && m.bw.limitKbps > 0 && m.bw.limitKbps < base {
			base = m.bw.limitKbps
		}
		ctl.capKbps = base * f
		if ctl.capKbps < cascadeMinCapKbps {
			ctl.capKbps = cascadeMinCapKbps
		}
		ctl.lastCut, ctl.haveCut, ctl.queueAtCut, ctl.cutFrom = now, true, queue, base
		ctl.blameless = sentKbps < 2*cascadeMinCapKbps
		return
	}

	// A queue that is building, but short of the target, means this path is
	// being given more than it delivers: an allowance above what arrives
	// only lets the queue climb until a cut. Trimming it to what is being
	// delivered makes the excess spill onto the next path at the link's real
	// rate instead. The lab showed the difference: without it a single flow
	// sat on one 20 Mbit link with a second idle.
	if rising && queue > cascadeTrimQueueMs && sentKbps >= 2*cascadeMinCapKbps {
		if ctl.capKbps == 0 || ctl.capKbps > delivered {
			ctl.capKbps = delivered
		}
	}
	ctl.overFor = 0
	if queue > target/2 {
		return // near the line: neither cut nor grow
	}
	ctl.clean++
	if ctl.blameless && ctl.clean >= need {
		ctl.capKbps, ctl.blameless = 0, false
		return
	}
	// Grow only an allowance something is pushing against: packets turned
	// away from it onto another path, or running close to it.
	inUse := demand.exhausted || sentKbps >= cascadeDemandShare*ctl.capKbps
	if ctl.capKbps == 0 || ctl.clean < need || !inUse {
		return
	}
	if ctl.capKbps < ctl.cutFrom/2 {
		ctl.capKbps *= cascadeFastGrowth
	} else {
		ctl.capKbps *= cascadeGrowth
	}
	if ctl.capKbps >= cascadeUnlimitedKbps {
		ctl.capKbps = 0
	}
}

// boundByPeak folds this evaluation's delivered rate into the peak windows
// and, once the path has congested at least once, holds its allowance to
// cascadePeakHeadroom above the recent peak. Before any congestion a path
// stays uncapped: filling the slowest link first until it shows it is full
// is S3.
func (ctl *capCtl) boundByPeak(now time.Duration, delivered float64) {
	if now-ctl.peakAt >= cascadePeakWindow {
		ctl.peakPrev, ctl.peakCur, ctl.peakAt = ctl.peakCur, 0, now
	}
	if delivered > ctl.peakCur {
		ctl.peakCur = delivered
	}
	peak := ctl.peakCur
	if ctl.peakPrev > peak {
		peak = ctl.peakPrev
	}
	switch {
	case !ctl.haveCut || ctl.blameless || ctl.capKbps == 0 && ctl.clean > 0:
		return
	case peak < cascadeMinCapKbps:
		return // nothing delivered lately; leave the allowance to the rules above
	}
	ceiling := peak * cascadePeakHeadroom
	if ctl.capKbps == 0 || ctl.capKbps > ceiling {
		ctl.capKbps = ceiling
	}
}

// bulkDeliveredKbps is how much of the bulk put onto a path over the last
// evaluation actually arrived. From the sender's side alone it is what was
// sent less the loss reported, which reads high whenever the link's buffer
// is absorbing the excess without dropping it - exactly while the link is
// full. The peer's receive rate (version 3) cannot read high that way, so
// when there is one the estimate is the lower of the two: the receive rate
// less whatever else is riding the path.
func bulkDeliveredKbps(m pathMetric, sentKbps float64) float64 {
	delivered := sentKbps * (1 - m.txShortLoss/100)
	if m.txRxKbps <= 0 || !m.haveTx {
		return delivered
	}
	other := m.bw.sendKbps - sentKbps
	if other < 0 {
		other = 0
	}
	if rx := m.txRxKbps - other; rx < delivered {
		delivered = rx
	}
	if delivered < 0 {
		delivered = 0
	}
	return delivered
}

// logCap reports a path's allowance changing between unlimited and capped,
// which is the transition worth reading at 2am. Every cut and growth step
// would bury the journal on the box hardest to reach.
func (s *scheduler) logCap(id uint8, protected bool, before, after float64) {
	if before == after {
		return
	}
	which := "bulk path"
	if protected {
		which = "call's path"
	}
	switch {
	case before == 0 && after > 0:
		log.Printf("cascade: %s (%s) bulk limited to %.0f kbps", s.pathName(id), which, after)
	case before > 0 && after == 0:
		log.Printf("cascade: %s (%s) uncapped again", s.pathName(id), which)
	}
}

// setCascadeActive logs the cascade starting and stopping.
func (s *scheduler) setCascadeActive(on bool, why string) {
	if s.cascadeLogged && s.cascadeWasOn == on && s.cascadeWhyLogged == why {
		return
	}
	first := !s.cascadeLogged
	s.cascadeLogged, s.cascadeWasOn, s.cascadeWhyLogged = true, on, why
	switch {
	case on:
		log.Printf("cascade: active, bulk spread per packet")
	case first && why == "no primary chosen yet":
		// The ordinary first evaluations; not worth a line.
	default:
		log.Printf("cascade: inactive (%s), bulk placed per flow", why)
	}
}

// pickCascade chooses the one path a bulk packet of size bytes goes out of
// (v0.2-design.md, section 5.3). It never drops.
//
// Allowances decide the split, not the total. When every path has spent its
// allowance the packet goes to the least-queued path (decision.overflowIdx),
// and the sending TCP finds the aggregate's limit from the links themselves,
// as it would anywhere. The first version dropped here whenever every
// allowance was spent, which made the tunnel a policer: TCP read the drops as
// the aggregate being full, never pushed past the first link, and the lab
// measured a two-link cascade carrying less than one link did per flow.
//
// Owned by the single goroutine reading the local endpoint: the token state
// is touched nowhere else, which is what lets this take no lock.
func (s *scheduler) pickCascade(d *decision, size int) ([]uint8, bool) {
	now := s.clock()
	for i, m := range d.cascade {
		id := m.id
		if m.capKbps <= 0 {
			s.bulkBytes[id].Add(uint64(size))
			return d.cascadeIDs[i : i+1], true
		}
		rate := m.capKbps * 125 // bytes a second
		depth := rate / 100     // 10 ms of it: see cascadeBucketNote
		if depth < cascadeMinBucketBytes {
			depth = cascadeMinBucketBytes
		}
		if elapsed := now - s.tokensAt[id]; elapsed > 0 {
			s.tokens[id] += rate * elapsed.Seconds()
			s.tokensAt[id] = now
		}
		if s.tokens[id] > depth {
			s.tokens[id] = depth
		}
		if s.tokens[id] >= float64(size) {
			s.tokens[id] -= float64(size)
			s.bulkBytes[id].Add(uint64(size))
			return d.cascadeIDs[i : i+1], true
		}
		s.exhaustedCount[id].Add(1)
	}
	if len(d.cascade) == 0 {
		return nil, false // not reachable: txForPacket only calls this with a cascade
	}
	i := d.overflowIdx
	s.bulkBytes[d.cascade[i].id].Add(uint64(size))
	s.overflowed.Add(1)
	return d.cascadeIDs[i : i+1], true
}

// cascadeBucketNote: the token buckets hold only 10 ms of allowance. A deeper
// bucket absorbs a sender's short excursions above the allowance - BBR's
// probe is a quarter above its rate for about a round trip - so they never
// spill onto the next path and the sender never sees that there was more
// capacity to be had. The lab measured a 100 ms bucket hiding every probe.
// A shallow bucket spills packet trains too, which costs nothing: spill is
// what the cascade is for, and every later path has its own allowance.
//
// cascadeMinBucketBytes lets a path at the floor still pass a full-sized
// packet or two.
const cascadeMinBucketBytes = 3000

// txForPacket is what the data path calls: the paths one packet goes out of,
// or false when it is to be dropped at the ingress. It differs from txFor only
// while the cascade is active, where bulk is placed per packet and
// transactional returns to the primary alone.
func (s *scheduler) txForPacket(class uint8, flow uint32, size int) ([]uint8, bool) {
	d := s.cur.Load()
	if !d.cascadeOn || class == protocol.ClassRealtime {
		return s.txFor(class, flow), true
	}
	if pin := s.pinnedPath(flow); pin != nil {
		return pin, true
	}
	if class == protocol.ClassBulk {
		return s.pickCascade(d, size)
	}
	// Transactional, and anything unplaced: the call's link, alone. S3 wants
	// page loads responsive on the low-latency path, and a request split
	// across links would be resequenced for nothing.
	if len(d.txTrans) > 0 {
		return d.txTrans, true
	}
	return d.tx, true
}

// describeCascade renders the cascade for the log.
func describeCascade(d *decision, name func(uint8) string) string {
	if !d.cascadeOn {
		return "per flow (" + d.cascadeWhy + ")"
	}
	parts := make([]string, 0, len(d.cascade))
	for _, m := range d.cascade {
		cap := "uncapped"
		if m.capKbps > 0 {
			cap = fmt.Sprintf("cap %.0f kbps", m.capKbps)
		}
		tag := ""
		if m.protected {
			tag = ", call's path"
		}
		parts = append(parts, fmt.Sprintf("%s (%s, carrying %.0f kbps%s)", name(m.id), cap, m.sentKbps, tag))
	}
	return strings.Join(parts, " -> ")
}
