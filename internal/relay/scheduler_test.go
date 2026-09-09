package relay

import (
	"testing"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
	"github.com/anthonysecco/OpenMultiPath/internal/usage"
)

// A synthetic world of paths the scheduler can be driven through. The
// conditions worth testing here - a canyon wall, an hour under forest
// canopy, a dead zone - cannot be produced on a bench, so they are
// described instead.
type world struct {
	paths map[uint8]pathMetric
	now   time.Duration
	c     config.Config
	s     *scheduler

	// mute names paths whose transmit direction is dead: they still
	// deliver to us but the peer never echoes anything we send on them.
	// Paths are asymmetric and this is a real failure, so it needs to be
	// expressible - it is what a handover to a one-way path looks like.
	mute map[uint8]bool
}

func newWorld(t *testing.T, paths ...pathMetric) *world {
	t.Helper()
	w := &world{paths: map[uint8]pathMetric{}, mute: map[uint8]bool{}, c: config.Defaults()}
	for _, p := range paths {
		w.paths[p.id] = p
	}

	w.s = &scheduler{
		cfg:      config.NewHolder(w.c),
		machines: map[uint8]*machine{},
		source: func(time.Duration) []pathMetric {
			out := make([]pathMetric, 0, len(w.paths))
			for _, p := range w.paths {
				out = append(out, p)
			}
			return out
		},
		candidates: func() []uint8 {
			out := []uint8{}
			for id, p := range w.paths {
				// A path with no socket cannot be transmitted on, which is
				// what the initiator's bound set means.
				if p.bound {
					out = append(out, id)
				}
			}
			return out
		},
	}
	w.s.cur.Store(emptyDecision)
	// The world models the D-020 shape, where payloads are plaintext and
	// classes are real. TestAdmissionDisabledWithoutClassification covers
	// the other one deliberately.
	w.s.setClassifying(true)
	return w
}

// tick advances the world by n evaluation intervals.
//
// A working path re-proves itself continuously - every echo the peer sends
// is fresh evidence that our transmissions are arriving - so confirmation
// is refreshed each interval rather than being a one-off event. Modelling
// it as a single moment made the handover tests pass for the wrong reason.
func (w *world) tick(n int) *decision {
	for i := 0; i < n; i++ {
		w.now += w.c.EvalInterval()
		for id, p := range w.paths {
			if !w.mute[id] && p.bound && p.silentFor < w.c.DownSilence() {
				p.confirmedAt = w.now
				w.paths[id] = p
			}
		}
		w.s.evaluate(w.now, w.c)
	}
	return w.s.current()
}

// set replaces one path's measurements.
func (w *world) set(id uint8, mutate func(*pathMetric)) {
	p := w.paths[id]
	mutate(&p)
	w.paths[id] = p
}

func path(id uint8, rttMs float64) pathMetric {
	return pathMetric{id: id, name: "test", bound: true, managed: true, rttMs: rttMs, burstRatio: 1}
}

func txSet(d *decision) map[uint8]bool {
	out := map[uint8]bool{}
	for _, id := range d.tx {
		out[id] = true
	}
	return out
}

// The regression that motivated all of this. With every packet riding every
// path, any real load saturates the weakest link - which on the 512k
// Starlink standby plan meant an 8000-packet collapse on a 10 MB copy. Two
// healthy paths must now carry traffic on one of them.
func TestHealthyPathsDoNotAllCarryEveryPacket(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 60))
	d := w.tick(w.c.PromoteIntervals + 5)

	if len(d.tx) != 1 {
		t.Fatalf("sending on %d paths (%v) with two healthy links, want exactly one", len(d.tx), d.tx)
	}
	if d.tx[0] != 0 {
		t.Errorf("chose path %d, want the lower-latency path 0", d.tx[0])
	}
}

// Principle 5. With nothing in a usable state the measurements have stopped
// being able to help, and sending everywhere at least has a chance.
func TestNoUsablePathFallsBackToSendingOnEverything(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 60))
	w.tick(w.c.PromoteIntervals + 5)

	// Both links go silent under active probing: a dead zone.
	for _, id := range []uint8{0, 1} {
		w.set(id, func(p *pathMetric) {
			p.silentFor = w.c.DownSilence() * 2
			p.sentSinceHeard = uint64(w.c.DownProbePackets) * 2
		})
	}
	d := w.tick(3)

	if !d.blind {
		t.Error("scheduler did not fall back to blind sending with every path down")
	}
	if len(d.tx) != 2 {
		t.Errorf("sending on %v, want every bound path so that something might get through", d.tx)
	}
}

// With no link at all there is nothing to send on, and the scheduler must
// say so rather than inventing a path.
func TestNothingBoundSendsNothing(t *testing.T) {
	w := newWorld(t, path(0, 40))
	w.set(0, func(p *pathMetric) { p.bound = false })

	if d := w.tick(3); len(d.tx) != 0 {
		t.Errorf("sending on %v with no bound link", d.tx)
	}
}

// Stickiness is mandatory. Without it an established flow oscillates every
// time two scores cross, and a conference call moves for no audible gain.
func TestMarginallyBetterPathDoesNotStealTheFlow(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 300))
	d := w.tick(w.c.PromoteIntervals + 5)
	if d.primary != 0 {
		t.Fatalf("primary is path %d, want path 0", d.primary)
	}

	// Path 1 becomes slightly better than path 0, but only slightly.
	w.set(0, func(p *pathMetric) { p.rttMs = 90 })
	w.set(1, func(p *pathMetric) { p.rttMs = 80 })

	d = w.tick(w.c.SwitchHoldIntervals * 4)
	if d.primary != 0 {
		t.Errorf("flow moved to path %d for a marginal gain; stickiness should have held it", d.primary)
	}
}

// A sustained, material improvement should win - after the hold, not
// instantly.
func TestSustainedlyBetterPathEventuallyWins(t *testing.T) {
	w := newWorld(t, path(0, 400), path(1, 400))
	w.tick(w.c.PromoteIntervals + 5)

	// Path 0 degrades badly while path 1 stays clean.
	w.set(0, func(p *pathMetric) { p.recentLoss = 8; p.burstRatio = 6 })

	d := w.tick(1)
	if d.primary != 0 {
		t.Error("flow moved on the very first bad interval; the challenger has to sustain it")
	}

	d = w.tick(w.c.SwitchHoldIntervals + w.c.MBBMaxMs/w.c.EvalIntervalMs + 5)
	if d.primary != 1 {
		t.Errorf("primary is still path %d after a sustained collapse on it", d.primary)
	}
}

// Never cut then connect. The overlap is the whole point: a gap is audible.
func TestHandoverOverlapsBeforeItCommits(t *testing.T) {
	w := newWorld(t, path(0, 400), path(1, 400))
	w.tick(w.c.PromoteIntervals + 5)

	// Collapse path 0 below the floor so the handover is urgent.
	w.set(0, func(p *pathMetric) { p.recentLoss = 40; p.burstRatio = 20 })

	// Find the interval on which the overlap begins.
	var d *decision
	for i := 0; i < 50; i++ {
		d = w.tick(1)
		if d.switching {
			break
		}
	}
	if !d.switching {
		t.Fatal("a collapsed primary never started a handover")
	}

	tx := txSet(d)
	if !tx[0] || !tx[1] {
		t.Errorf("during the handover traffic is on %v, want both the old and new path", d.tx)
	}
	if d.primary != 0 {
		t.Errorf("primary changed to %d before the new path was confirmed", d.primary)
	}

	// Confirmation is the peer echoing something we sent on the new path.
	// Receiving on it proves the reverse direction only, and a path can be
	// clean inbound and dead outbound.
	d = w.tick(w.c.MBBMinMs/w.c.EvalIntervalMs + 2)

	if d.switching {
		t.Error("handover never completed after the new path was confirmed")
	}
	if d.primary != 1 {
		t.Errorf("primary is path %d after a completed handover, want path 1", d.primary)
	}
	if len(d.tx) != 1 {
		t.Errorf("still sending on %v after the handover completed", d.tx)
	}
}

// Paying double forever is worse than committing. The new path was chosen
// because the old one was failing.
func TestUnconfirmedHandoverCommitsAtTheDeadline(t *testing.T) {
	w := newWorld(t, path(0, 400), path(1, 400))
	w.tick(w.c.PromoteIntervals + 5)
	w.set(0, func(p *pathMetric) { p.recentLoss = 40; p.burstRatio = 20 })

	// Path 1 delivers to us but nothing we send on it is ever echoed
	// back, so the handover can never be confirmed.
	w.mute[1] = true
	d := w.tick(50 + w.c.MBBMaxMs/w.c.EvalIntervalMs)
	if d.switching {
		t.Error("an unconfirmed handover is still overlapping past its deadline")
	}
	if d.primary != 1 {
		t.Errorf("primary is path %d, want the handover committed to path 1", d.primary)
	}
}

// The canyon approach from scope-v1.md. Starlink degrades; the call should
// end up on 5G, and Starlink must not be carrying it any more.
func TestCanyonApproachMovesTheCallOffTheDegradingLink(t *testing.T) {
	starlink, cellular := path(0, 60), path(1, 90)
	w := newWorld(t, starlink, cellular)
	w.tick(w.c.PromoteIntervals + 5)

	if w.s.current().primary != 0 {
		t.Fatal("call did not start on the better path")
	}

	// The canyon wall: loss arrives in long runs, which is what a dish
	// losing sight of the sky looks like.
	w.set(0, func(p *pathMetric) { p.recentLoss = 15; p.burstRatio = 12; p.jitterMs = 80 })

	d := w.tick(60)
	if d.primary != 1 {
		t.Fatalf("call is still on path %d after the canyon", d.primary)
	}
	if txSet(d)[0] {
		t.Error("still sending on the degraded link after the handover completed")
	}
}

// Emerging from the canyon: Starlink returns and immediately looks
// excellent. It must not take the call straight back, because it has proved
// only that it can deliver a packet.
func TestRecoveredLinkDoesNotImmediatelyTakeTheCallBack(t *testing.T) {
	w := newWorld(t, path(0, 60), path(1, 90))
	w.tick(w.c.PromoteIntervals + 5)

	w.set(0, func(p *pathMetric) { p.recentLoss = 15; p.burstRatio = 12 })
	w.tick(60)
	if w.s.current().primary != 1 {
		t.Fatal("call never moved off the degraded path")
	}

	// Starlink comes back looking perfect.
	w.set(0, func(p *pathMetric) { p.recentLoss = 0; p.burstRatio = 1; p.rttMs = 40 })

	d := w.tick(2)
	if d.primary != 1 {
		t.Errorf("call jumped straight back to path %d on a couple of good intervals", d.primary)
	}
}

func TestDuplicateAlwaysUsesEveryUsablePath(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 60), path(2, 80))
	w.c.DuplicateMode = config.DuplicateAlways
	w.s.cfg = config.NewHolder(w.c)

	d := w.tick(w.c.PromoteIntervals + 5)
	if len(d.tx) != 3 {
		t.Errorf("sending on %v, want every usable path in always mode", d.tx)
	}
}

func TestDuplicateOffSendsOneCopyOutsideHandovers(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 60))
	w.c.DuplicateMode = config.DuplicateOff
	w.s.cfg = config.NewHolder(w.c)

	d := w.tick(w.c.PromoteIntervals + 5)
	if len(d.tx) != 1 {
		t.Errorf("sending on %v in off mode, want a single copy", d.tx)
	}
}

// Duplication is insurance. Taking out three policies on a link with none
// to spare is how the insurance becomes the accident - which on a 512k
// standby plan is not hypothetical.
func TestDuplicateUnstableAddsExactlyOneSpareCopy(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 60), path(2, 80))
	w.c.DuplicateMode = config.DuplicateUnstable
	w.s.cfg = config.NewHolder(w.c)
	w.tick(w.c.PromoteIntervals + 5)

	// Degrade the primary just enough to make it unstable, without
	// collapsing it below the floor and triggering a handover instead.
	w.set(0, func(p *pathMetric) { p.jitterMs = float64(w.c.UnstableJitterMs) + 10 })

	d := w.tick(w.c.DemoteIntervals + 2)
	if len(d.tx) != 2 {
		t.Errorf("sending on %v with a degraded primary, want the primary plus one spare", d.tx)
	}
	if !txSet(d)[d.primary] {
		t.Errorf("primary path %d is not among the paths being sent on (%v)", d.primary, d.tx)
	}
}

// The ranking is what architecture.md's fallback reads when the scheduler
// is the thing that has died, so it has to be present and ordered.
func TestRankingIsPublishedBestFirst(t *testing.T) {
	w := newWorld(t, path(0, 400), path(1, 40), path(2, 90))
	d := w.tick(w.c.PromoteIntervals + 5)

	if len(d.ranking) != 3 {
		t.Fatalf("ranking is %v, want every eligible path", d.ranking)
	}
	if d.ranking[0] != 1 {
		t.Errorf("ranking leads with path %d, want the best path 1: %v", d.ranking[0], d.ranking)
	}
	for i := 1; i < len(d.ranking); i++ {
		lo := d.views[uint8(d.ranking[i])].Score
		hi := d.views[uint8(d.ranking[i-1])].Score
		if lo > hi {
			t.Errorf("ranking is out of order at %d: %v", i, d.ranking)
		}
	}
}

// The published view is what the interface and the history log read, so it
// has to describe every path, not just the chosen one.
func TestEveryPathIsDescribedInThePublishedView(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 60))
	w.set(1, func(p *pathMetric) { p.bound = false })

	d := w.tick(w.c.PromoteIntervals + 5)
	for _, id := range []uint8{0, 1} {
		v, ok := d.views[id]
		if !ok {
			t.Errorf("path %d has no published view", id)
			continue
		}
		if v.State == "" {
			t.Errorf("path %d has an empty state", id)
		}
	}
	if d.views[1].State != stateDown.String() {
		t.Errorf("unbound path 1 shows as %q, want down", d.views[1].State)
	}
	if d.views[0].Sending != true {
		t.Error("the chosen path is not marked as sending")
	}
}

// Two paths that are both comfortably below the delay knee both score the
// maximum, because the model measures impairment and neither is impaired.
// That is correct and useless for choosing between them, so the tie has to
// break on something meaningful. Before this, it broke on map iteration
// order landing on the lowest path id - and path 0 is the metered satellite
// link, so the accident always went the expensive way.
func TestTiedScoresBreakTowardsTheLowerDelay(t *testing.T) {
	// Path 0 is the slower link but both are well inside the knee.
	w := newWorld(t, path(0, 70), path(1, 30))
	d := w.tick(w.c.PromoteIntervals + 5)

	if a, b := d.views[0].Score, d.views[1].Score; a != b {
		t.Skipf("paths did not tie (%.1f vs %.1f); the tie-break is not what is under test", a, b)
	}
	if d.primary != 1 {
		t.Errorf("tie broke towards path %d, want the lower-delay path 1", d.primary)
	}
	if d.ranking[0] != 1 {
		t.Errorf("ranking leads with path %d, want path 1: %v", d.ranking[0], d.ranking)
	}
}

// The scenario that produced D-023. A large transfer is running on the good
// path, that path degrades, and duplication looks for somewhere to put a
// second copy. The only other path is the 512k satellite standby link,
// which has been carrying nothing but probes and therefore scores
// beautifully - no queue, no loss, nothing to go wrong yet. Sending it a
// mirror of a multi-megabit transfer is how a 10 MB copy produced eight
// thousand lost packets.
func TestDuplicationSkipsAPathTooSmallForTheLoad(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 30))
	w.c.DuplicateMode = config.DuplicateUnstable
	w.s.cfg = config.NewHolder(w.c)

	// Path 1 carries the transfer at 6 Mbps. Path 0 is the satellite link,
	// idle, with a ceiling measured back when something did use it.
	w.set(1, func(p *pathMetric) { p.bw = bwView{sendKbps: 6000, limitKbps: 40000, haveCeiling: true} })
	w.set(0, func(p *pathMetric) { p.bw = bwView{sendKbps: 10, limitKbps: 512, haveCeiling: true} })
	w.tick(w.c.PromoteIntervals + 5)

	// Path 1 goes bad enough to be called unstable, which is what turns
	// duplication on.
	w.set(1, func(p *pathMetric) { p.recentLoss = 3 })
	d := w.tick(w.c.DemoteIntervals + 2)

	if d.primary != 1 {
		t.Fatalf("primary is path %d, want the transfer to still be on path 1", d.primary)
	}
	if txSet(d)[0] {
		t.Errorf("duplicated a 6 Mbps stream onto a 512 kbps path: tx %v (%s)", d.tx, d.reason)
	}
	if len(d.tx) != 1 {
		t.Errorf("tx = %v, want the primary alone when nothing can take a copy", d.tx)
	}
}

// The same shape, with a path that genuinely has room. The gate must not
// have simply disabled duplication.
func TestDuplicationUsesAPathWithTheCapacity(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 30))
	w.c.DuplicateMode = config.DuplicateUnstable
	w.s.cfg = config.NewHolder(w.c)

	w.set(1, func(p *pathMetric) { p.bw = bwView{sendKbps: 6000, limitKbps: 40000, haveCeiling: true} })
	w.set(0, func(p *pathMetric) { p.bw = bwView{sendKbps: 10, limitKbps: 25000, haveCeiling: true} })
	w.tick(w.c.PromoteIntervals + 5)

	w.set(1, func(p *pathMetric) { p.recentLoss = 3 })
	d := w.tick(w.c.DemoteIntervals + 2)

	if !txSet(d)[0] {
		t.Errorf("did not duplicate onto a path with ample headroom: tx %v (%s)", d.tx, d.reason)
	}
}

// A path nothing has ever loaded has no estimate, and no estimate must mean
// permission. Refusing on ignorance would make a link ineligible for having
// been quiet, which on a box whose links are quiet most of the time is the
// same as switching duplication off.
func TestDuplicationAllowedWhenCapacityIsUnknown(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 30))
	w.c.DuplicateMode = config.DuplicateUnstable
	w.s.cfg = config.NewHolder(w.c)

	w.set(1, func(p *pathMetric) { p.bw = bwView{sendKbps: 6000, limitKbps: 40000, haveCeiling: true} })
	// Path 0: never loaded, so limitKbps is zero - no opinion.
	w.tick(w.c.PromoteIntervals + 5)

	w.set(1, func(p *pathMetric) { p.recentLoss = 3 })
	d := w.tick(w.c.DemoteIntervals + 2)

	if !txSet(d)[0] {
		t.Errorf("refused a path with no capacity estimate: tx %v (%s)", d.tx, d.reason)
	}
}

// A better-scoring path that cannot carry what the primary is carrying is a
// smaller path, not a better one. Moving a running transfer onto it would
// trade the transfer for a nicer set of numbers.
func TestHandoverBlockedByCapacityWhenMerelyOpportunistic(t *testing.T) {
	w := newWorld(t, path(0, 20), path(1, 60))
	w.set(1, func(p *pathMetric) { p.bw = bwView{sendKbps: 6000, limitKbps: 40000, haveCeiling: true} })
	w.set(0, func(p *pathMetric) { p.bw = bwView{sendKbps: 10, limitKbps: 512, haveCeiling: true} })

	// Start with path 1 as primary by making path 0 briefly unavailable.
	w.set(0, func(p *pathMetric) { p.bound = false })
	w.tick(w.c.PromoteIntervals + 5)
	if d := w.s.current(); d.primary != 1 {
		t.Fatalf("primary is path %d, want path 1 to start", d.primary)
	}
	w.set(0, func(p *pathMetric) { p.bound = true })

	d := w.tick(w.c.PromoteIntervals + w.c.SwitchHoldIntervals + 10)
	if d.primary != 1 {
		t.Errorf("handed a 6 Mbps transfer to path %d, which is estimated at 512 kbps", d.primary)
	}
}

// The gate is soft. When the current path has fallen below the floor it is
// failing, and a small path that works beats a large one that does not -
// principle 5, fail to a working state.
func TestHandoverToASmallPathStillHappensBelowTheFloor(t *testing.T) {
	w := newWorld(t, path(0, 20), path(1, 60))
	w.set(1, func(p *pathMetric) { p.bw = bwView{sendKbps: 6000, limitKbps: 40000, haveCeiling: true} })
	w.set(0, func(p *pathMetric) { p.bw = bwView{sendKbps: 10, limitKbps: 512, haveCeiling: true} })

	w.set(0, func(p *pathMetric) { p.bound = false })
	w.tick(w.c.PromoteIntervals + 5)
	w.set(0, func(p *pathMetric) { p.bound = true })
	w.tick(w.c.PromoteIntervals + 2)

	// Path 1 collapses: heavy, clustered loss drives it under min_acceptable_r.
	w.set(1, func(p *pathMetric) { p.recentLoss = 25; p.burstRatio = 6; p.jitterMs = 120 })
	d := w.tick(w.c.SwitchHoldIntervals + 20)

	if d.primary != 0 {
		t.Errorf("primary is path %d; a failing path must be left even for a small one (%s)", d.primary, d.reason)
	}
}

// Observed on the road, 2026-09-01. Both paths healthy and scoring 93.2 -
// identical, because the E-model measures impairment and neither is
// impaired. Path 0 is the 512 kbps satellite standby link and happens to be
// primary; path 1 is cellular with four times the measured capacity and is
// idle. Nothing could ever move the flow, because a challenger must beat
// the incumbent by SwitchMarginR and a tie never will, so upload sat at
// 0.45 Mbps with a multi-megabit link beside it.
func TestTiedQualityBreaksTowardsCapacity(t *testing.T) {
	w := newWorld(t, path(0, 30), path(1, 35))
	w.set(0, func(p *pathMetric) { p.bw = bwView{sendKbps: 3, limitKbps: 506, haveCeiling: true} })
	w.set(1, func(p *pathMetric) { p.bw = bwView{sendKbps: 5, limitKbps: 2071, haveCeiling: true} })

	// Establish path 0 as primary the way the field case did.
	w.set(1, func(p *pathMetric) { p.bound = false })
	w.tick(w.c.PromoteIntervals + 5)
	if d := w.s.current(); d.primary != 0 {
		t.Fatalf("primary is path %d, want path 0 to start", d.primary)
	}
	w.set(1, func(p *pathMetric) { p.bound = true })

	d := w.tick(w.c.PromoteIntervals + w.c.SwitchHoldIntervals + 10)

	if a, b := d.views[0].Score, d.views[1].Score; a != b {
		t.Fatalf("paths did not tie (%.1f vs %.1f); this test is about the tie", a, b)
	}
	if d.primary != 1 {
		t.Errorf("primary stayed on path %d (506 kbps) with 2071 kbps available (%s)", d.primary, d.reason)
	}
}

// The same rule must not run the other way. A primary with plenty of room
// is not displaced by a smaller path, however good it looks.
func TestCapacityNeverMovesOntoASmallerPath(t *testing.T) {
	w := newWorld(t, path(0, 30), path(1, 35))
	w.set(0, func(p *pathMetric) { p.bw = bwView{sendKbps: 3, limitKbps: 506, haveCeiling: true} })
	w.set(1, func(p *pathMetric) { p.bw = bwView{sendKbps: 5, limitKbps: 2071, haveCeiling: true} })

	w.set(0, func(p *pathMetric) { p.bound = false })
	w.tick(w.c.PromoteIntervals + 5)
	w.set(0, func(p *pathMetric) { p.bound = true })

	d := w.tick(w.c.PromoteIntervals + w.c.SwitchHoldIntervals + 10)
	if d.primary != 1 {
		t.Errorf("primary moved from the 2071 kbps path to path %d (%s)", d.primary, d.reason)
	}
}

// Capacity only speaks when it has been measured. An unmeasured path is not
// evidence of a large link any more than of a small one, and must not
// displace a working primary on a number nobody has.
func TestUnmeasuredCapacityDoesNotMovePrimary(t *testing.T) {
	w := newWorld(t, path(0, 30), path(1, 35))
	w.set(0, func(p *pathMetric) { p.bw = bwView{sendKbps: 3, limitKbps: 506, haveCeiling: true} })
	// Path 1 has no estimate at all.

	w.set(1, func(p *pathMetric) { p.bound = false })
	w.tick(w.c.PromoteIntervals + 5)
	w.set(1, func(p *pathMetric) { p.bound = true })

	d := w.tick(w.c.PromoteIntervals + w.c.SwitchHoldIntervals + 10)
	if d.primary != 0 {
		t.Errorf("primary moved to path %d on an unmeasured capacity (%s)", d.primary, d.reason)
	}
}

// The failure that motivated step 6c, reproduced.
//
// A download saturates path 1's DOWNLINK. Every statistic this node can
// gather locally is measured on arriving packets, so all of them show path 1
// collapsing: the round trip balloons, inbound spread and queue delay go
// with it. Path 1's UPLINK is untouched and idle throughout.
//
// Scored on inbound evidence the flow gets evacuated onto path 0 - which on
// the vehicle is a 512 kbps standby link - and upload falls to 0.45 Mbps.
// Scored on what the peer reports about our send direction, nothing has
// happened and the flow stays put.
func TestInboundCongestionDoesNotMoveTheOutboundFlow(t *testing.T) {
	w := newWorld(t, path(0, 30), path(1, 30))

	// Both ends are reporting, and both send directions are clean.
	clean := func(p *pathMetric) {
		p.haveTx, p.rttFloorMs = true, 30
		p.txSpreadMs, p.txQueueMs, p.txLoss, p.txBurstRatio = 2, 1, 0, 1
	}
	w.set(0, clean)
	w.set(1, clean)
	w.tick(w.c.PromoteIntervals + 5)

	if d := w.s.current(); d.primary != 0 && d.primary != 1 {
		t.Fatalf("no primary settled: %+v", d)
	}
	started := w.s.current().primary

	// The download lands. Path 1's inbound numbers fall apart - 756 ms of
	// loaded latency was what the field measured - while its send direction,
	// which the peer is still reporting on, stays clean.
	w.set(1, func(p *pathMetric) {
		p.rttMs = 760
		p.p95SpreadMs = 700
		p.queueDelayMs = 700
		p.recentLoss = 12
		p.burstRatio = 4
	})
	d := w.tick(w.c.SwitchHoldIntervals + 20)

	if d.primary != started {
		t.Errorf("inbound congestion moved the outbound flow from path %d to path %d (%s)",
			started, d.primary, d.reason)
	}
}

// The converse, which is the whole point of measuring the right direction:
// when the peer says our SEND direction on the primary has fallen apart,
// the flow does move - even though everything measured locally looks fine.
func TestOutboundDegradationMovesTheFlow(t *testing.T) {
	w := newWorld(t, path(0, 30), path(1, 30))
	clean := func(p *pathMetric) {
		p.haveTx, p.rttFloorMs = true, 30
		p.txSpreadMs, p.txQueueMs, p.txLoss, p.txBurstRatio = 2, 1, 0, 1
	}
	w.set(0, clean)
	w.set(1, clean)

	w.set(1, func(p *pathMetric) { p.bound = false })
	w.tick(w.c.PromoteIntervals + 5)
	w.set(1, func(p *pathMetric) { p.bound = true })
	w.tick(w.c.PromoteIntervals + 2)
	if d := w.s.current(); d.primary != 0 {
		t.Fatalf("primary is path %d, want path 0 to start", d.primary)
	}

	// Locally path 0 still looks perfect. The peer says otherwise.
	w.set(0, func(p *pathMetric) {
		p.txSpreadMs, p.txQueueMs = 400, 380
		p.txLoss, p.txBurstRatio = 20, 5
	})
	d := w.tick(w.c.SwitchHoldIntervals + 20)

	if d.primary != 1 {
		t.Errorf("primary stayed on path %d despite the peer reporting it unusable outbound (%s)",
			d.primary, d.reason)
	}
}

// Without a report there is nothing to score on but the round trip, which
// is what every build before this did. It has to keep working: an old peer,
// or a path the far end has not heard from, must not become unschedulable.
func TestFallsBackToRoundTripWithoutAReport(t *testing.T) {
	w := newWorld(t, path(0, 30), path(1, 90))
	d := w.tick(w.c.PromoteIntervals + 5)

	if !d.havePrimary {
		t.Fatal("no primary chosen with no path reports available")
	}
	if d.primary != 0 {
		t.Errorf("primary is path %d, want the lower-latency path 0 on round-trip scoring", d.primary)
	}
}

// bulkSet is txSet for the other class.
func bulkSet(d *decision) map[uint8]bool {
	out := map[uint8]bool{}
	for _, id := range d.txBulk {
		out[id] = true
	}
	return out
}

// Step 8, and the reason step 7 was worth doing. Duplication is insurance
// for the call; buying it for a download is how the 512k standby link got
// saturated in the first place (D-022). Even told to duplicate on
// everything, bulk must ride one path.
func TestBulkIsNeverDuplicatedEvenWhenToldTo(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 60))
	w.c.DuplicateMode = config.DuplicateAlways
	d := w.tick(w.c.PromoteIntervals + 5)

	if len(d.tx) < 2 {
		t.Fatalf("real-time is on %d paths (%v) under duplicate-always, want more than one", len(d.tx), d.tx)
	}
	if len(d.txBulk) != 1 {
		t.Errorf("bulk is on %d paths (%v) under duplicate-always, want exactly one", len(d.txBulk), d.txBulk)
	}
	if d.txBulk[0] != d.primary {
		t.Errorf("bulk is on path %d, want the primary %d", d.txBulk[0], d.primary)
	}
}

// The same policy applied to the class it was written for.
func TestRealtimeDuplicatesWhileTheChosenPathIsDegraded(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 60))
	w.c.DuplicateMode = config.DuplicateUnstable
	w.tick(w.c.PromoteIntervals + 5)

	// Both links degrade together, which is what a canyon does - degrading
	// only one would simply hand the flow to the other, and then the
	// primary is not degraded and there is nothing to insure against.
	for _, id := range []uint8{0, 1} {
		w.set(id, func(p *pathMetric) { p.recentLoss = float64(w.c.UnstableLossPercent) + 2 })
	}
	d := w.tick(w.c.DemoteIntervals + 3)
	if d.blind {
		t.Skip("world went blind; that path is covered by its own test")
	}

	if len(d.tx) < 2 {
		t.Errorf("real-time is on %d paths (%v) with a degraded primary, want a second copy", len(d.tx), d.tx)
	}
	if len(d.txBulk) != 1 {
		t.Errorf("bulk followed real-time onto %d paths (%v), want one", len(d.txBulk), d.txBulk)
	}
}

// Make-before-break is scoped to real-time in scope-v1.md. Paying double
// for a download during exactly the window the call needs the capacity is
// the wrong trade, and TCP will sort out what a switch costs it.
func TestMakeBeforeBreakCarriesRealtimeOnBothAndBulkOnOne(t *testing.T) {
	w := newWorld(t, path(0, 20), path(1, 30))
	w.tick(w.c.PromoteIntervals + 5)
	if d := w.s.current(); d.primary != 0 {
		t.Fatalf("primary is %d, want path 0 to start", d.primary)
	}

	// Push the primary below the floor so a handover starts.
	w.set(0, func(p *pathMetric) { p.rttMs = 900; p.recentLoss = 20 })

	var seen bool
	for i := 0; i < 40; i++ {
		d := w.tick(1)
		if !d.switching {
			continue
		}
		seen = true
		if len(d.tx) < 2 {
			t.Errorf("mid-handover real-time is on %d paths (%v), want both", len(d.tx), d.tx)
		}
		if len(d.txBulk) != 1 {
			t.Errorf("mid-handover bulk is on %d paths (%v), want one", len(d.txBulk), d.txBulk)
		}
		break
	}
	if !seen {
		t.Skip("no handover window observed; covered by the handover tests above")
	}
}

// Principle 5. With nothing usable there is no measurement left to tell the
// classes apart with, so withholding bulk would be acting on a distinction
// nothing can currently support.
func TestBlindModeSpraysBothClasses(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 60))
	w.tick(w.c.PromoteIntervals + 5)
	for _, id := range []uint8{0, 1} {
		w.set(id, func(p *pathMetric) { p.silentFor = w.c.DownSilence() * 2; p.sentSinceHeard = 100 })
	}
	d := w.tick(w.c.DemoteIntervals + 5)

	if !d.blind {
		t.Skip("world did not reach blind mode")
	}
	if len(d.tx) == 0 || len(d.txBulk) == 0 {
		t.Errorf("blind mode carries real-time on %v and bulk on %v; both must be sent somewhere", d.tx, d.txBulk)
	}
	if len(d.tx) != len(d.txBulk) {
		t.Errorf("blind mode split the classes, real-time %v against bulk %v", d.tx, d.txBulk)
	}
}

// Transactional takes the call's path and none of the call's redundancy.
//
// The first half is the point of the class: a web request wants the same
// link real-time wants - shortest round trip, least loss - and exiling it
// with the downloads is what made page loads slow. The second half is the
// invariant the old two-class test was really defending: a second copy of
// a request is unbounded cost for a flow TCP recovers in one RTT.
func TestTransactionalRidesTheCallsPathWithoutItsDuplication(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 60))
	w.c.DuplicateMode = config.DuplicateAlways
	w.s.cfg = config.NewHolder(w.c)
	d := w.tick(w.c.PromoteIntervals + 5)

	if len(d.tx) != 2 {
		t.Fatalf("setup: real-time on %v, want both paths in always mode", d.tx)
	}

	trans := w.s.txPaths(protocol.ClassTransactional)
	bulk := w.s.txPaths(protocol.ClassBulk)

	if len(trans) != 1 || trans[0] != d.primary {
		t.Errorf("transactional took %v, want the primary %d alone", trans, d.primary)
	}
	if sameSet(trans, bulk) && len(bulk) > 0 && bulk[0] != d.primary {
		t.Errorf("transactional took %v, the same as bulk's %v; it was exiled with the downloads", trans, bulk)
	}
}

// Anything the classifier could not place rides with transactional, not
// with bulk. That reverses D-027 on purpose: with three classes the safe
// default is the middle, because an unplaced flow has by definition not
// moved much data.
func TestUnknownRidesWithTransactional(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 60))
	w.tick(w.c.PromoteIntervals + 5)

	if !sameSet(w.s.txPaths(protocol.ClassUnknown), w.s.txPaths(protocol.ClassTransactional)) {
		t.Errorf("unclassified took %v but transactional took %v",
			w.s.txPaths(protocol.ClassUnknown), w.s.txPaths(protocol.ClassTransactional))
	}
}

// The correction the class was really for. Admission control exists to
// stop a download adding hundreds of milliseconds to a call; withholding
// a web request instead destroys the traffic the user is watching to
// protect the traffic they are listening to.
func TestTransactionalIsNeverWithheld(t *testing.T) {
	w := newWorld(t, path(0, 40))
	w.tick(w.c.PromoteIntervals + 5)

	w.set(0, func(p *pathMetric) {
		p.haveTx = true
		p.txQueueMs = float64(w.c.AdmissionQueueDelayMs) * 4
	})
	d := w.tick(1)

	if !d.withholdBulk {
		t.Fatal("setup: the gate did not shut on a queueing sole path")
	}
	if !w.s.admit(protocol.ClassTransactional) {
		t.Error("a web request was withheld to protect the call")
	}
	if !w.s.admit(protocol.ClassRealtime) {
		t.Error("real-time withheld; it has an absolute reservation")
	}
	if w.s.admit(protocol.ClassBulk) {
		t.Error("bulk admitted while the gate is shut; it is still the sacrificial class")
	}
}

// Blind mode sprays every class alike, transactional included: there is
// no measurement left to tell them apart with.
func TestBlindModeSpraysTransactionalToo(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 60))
	w.tick(w.c.PromoteIntervals + 5)

	for _, id := range []uint8{0, 1} {
		w.set(id, func(p *pathMetric) {
			p.silentFor = w.c.DownSilence() * 2
			p.sentSinceHeard = uint64(w.c.DownProbePackets) * 2
		})
	}
	d := w.tick(3)

	if !d.blind {
		t.Fatal("expected blind mode with every path down")
	}
	if !sameSet(w.s.txPaths(protocol.ClassTransactional), d.tx) {
		t.Errorf("blind mode sent transactional on %v and real-time on %v",
			w.s.txPaths(protocol.ClassTransactional), d.tx)
	}
}

// Step 9, and the canyon case scope-v1.md walks through: one path left, a
// download filling its uplink, and hundreds of milliseconds of standing
// queue landing on the call. Bulk is the sacrificial class and has to go.
func TestBulkStarvedWhenTheCallsPathIsQueueing(t *testing.T) {
	w := newWorld(t, path(0, 40))
	w.tick(w.c.PromoteIntervals + 5)

	w.set(0, func(p *pathMetric) {
		p.haveTx = true
		p.txQueueMs = float64(w.c.AdmissionQueueDelayMs) * 2
	})
	d := w.tick(1)

	if !d.withholdBulk {
		t.Fatal("bulk still admitted with the call's own path queueing")
	}
	if !w.s.admit(protocol.ClassRealtime) {
		t.Error("real-time withheld; scope-v1.md gives it an absolute reservation")
	}
	if w.s.admit(protocol.ClassBulk) {
		t.Error("bulk admitted while the gate is shut")
	}
	// D-027: anything not positively identified as real-time is carried as
	// bulk, and that has to include being starved as bulk.
	if w.s.admit(protocol.ClassUnknown) {
		t.Error("unclassified admitted while the gate is shut")
	}
}

// The queue that matters is the one our own bulk fills, which is the send
// direction and is only ever known from what the peer reports. Acting on a
// figure measured on arriving packets would starve a download for a
// downlink it is not responsible for. See D-024.
func TestBulkAdmittedWithoutSendDirectionEvidence(t *testing.T) {
	w := newWorld(t, path(0, 40))
	w.tick(w.c.PromoteIntervals + 5)

	w.set(0, func(p *pathMetric) {
		p.haveTx = false
		p.txQueueMs = float64(w.c.AdmissionQueueDelayMs) * 4
	})

	if d := w.tick(1); d.withholdBulk {
		t.Error("bulk starved with nobody having reported our send direction")
	}
}

// Asymmetric, for the same reason the path machine is: shutting is cheap
// and reversible, and reopening early costs the call another burst of
// standing queue.
func TestBulkReadmittedOnlyAfterTheQueueStaysClear(t *testing.T) {
	w := newWorld(t, path(0, 40))
	w.tick(w.c.PromoteIntervals + 5)

	w.set(0, func(p *pathMetric) {
		p.haveTx = true
		p.txQueueMs = float64(w.c.AdmissionQueueDelayMs) * 2
	})
	if d := w.tick(1); !d.withholdBulk {
		t.Fatal("gate did not shut on the first evaluation over the line")
	}

	w.set(0, func(p *pathMetric) { p.txQueueMs = 0 })
	if d := w.tick(w.c.AdmissionRecoverIntervals - 1); !d.withholdBulk {
		t.Error("gate reopened before the queue had stayed clear long enough")
	}
	if d := w.tick(2); d.withholdBulk {
		t.Error("gate never reopened after the queue stayed clear")
	}
}

// Principle 5. In blind mode the measurements have stopped being able to
// say anything, and withholding half the traffic would be acting on a
// distinction nothing can currently support.
func TestBlindModeNeverStarvesBulk(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 60))
	w.tick(w.c.PromoteIntervals + 5)

	for _, id := range []uint8{0, 1} {
		w.set(id, func(p *pathMetric) {
			p.haveTx = true
			p.txQueueMs = float64(w.c.AdmissionQueueDelayMs) * 4
			p.silentFor = w.c.DownSilence() * 2
			p.sentSinceHeard = uint64(w.c.DownProbePackets) * 2
		})
	}
	d := w.tick(3)

	if !d.blind {
		t.Fatal("expected blind mode with every path down")
	}
	if d.withholdBulk {
		t.Error("bulk starved in blind mode, where nothing can justify it")
	}
}

// Below WireGuard the payload is ciphertext, nothing can be classified,
// and every packet arrives as ClassUnknown. A gate that treats unknown as
// bulk would then withhold the call along with the download - taking the
// tunnel down at exactly the moment the link is congested. Admission
// control has to be off entirely where classes are not real.
func TestAdmissionDisabledWithoutClassification(t *testing.T) {
	w := newWorld(t, path(0, 40))
	w.s.setClassifying(false)
	w.tick(w.c.PromoteIntervals + 5)

	w.set(0, func(p *pathMetric) {
		p.haveTx = true
		p.txQueueMs = float64(w.c.AdmissionQueueDelayMs) * 4
	})
	d := w.tick(1)

	if d.withholdBulk {
		t.Error("gate shut with no classifier; unknown traffic includes the call")
	}
	if !w.s.admit(protocol.ClassUnknown) {
		t.Error("unclassified traffic withheld below WireGuard, where it may be the call")
	}
}

// Step 8's remaining half. With a second path usable, a download has no
// business sharing the link carrying the call: the queue it builds arrives
// as delay in a meeting, and the cost of moving it is a slower page.
func TestBulkIsSteeredOffTheCallsPath(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 60))
	d := w.tick(w.c.PromoteIntervals + 5)

	if len(d.txBulk) != 1 {
		t.Fatalf("bulk on %v, want exactly one path", d.txBulk)
	}
	if d.txBulk[0] == d.primary {
		t.Errorf("bulk on path %d, the same path as the call, with another usable", d.txBulk[0])
	}
	if len(d.tx) != 1 || d.tx[0] != d.primary {
		t.Errorf("real-time on %v, want the primary alone", d.tx)
	}
}

// The condition admission control exists for. One path means there is
// nowhere to steer to, so the classes share and step 9 decides whether
// bulk flows at all.
func TestBulkSharesThePrimaryWhenNothingElseIsUsable(t *testing.T) {
	w := newWorld(t, path(0, 40))
	d := w.tick(w.c.PromoteIntervals + 5)

	if len(d.txBulk) != 1 || d.txBulk[0] != d.primary {
		t.Fatalf("bulk on %v with one usable path, want the primary", d.txBulk)
	}

	w.set(0, func(p *pathMetric) {
		p.haveTx = true
		p.txQueueMs = float64(w.c.AdmissionQueueDelayMs) * 2
	})
	if d := w.tick(1); !d.withholdBulk {
		t.Error("classes share the only path and it is queueing, but bulk was not withheld")
	}
}

// Steering is the better answer than starving whenever both are available,
// so the two have to compose: once bulk is on a path of its own, its queue
// is nobody else's problem and the gate must stay open.
func TestSteeringBulkAwayRemovesTheNeedToStarveIt(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 60))
	w.tick(w.c.PromoteIntervals + 5)

	// The call's path is queueing hard in our send direction.
	w.set(0, func(p *pathMetric) {
		p.haveTx = true
		p.txQueueMs = float64(w.c.AdmissionQueueDelayMs) * 4
	})
	d := w.tick(1)

	if d.withholdBulk {
		t.Error("bulk starved while it was already riding a path of its own")
	}
	if d.txBulk[0] == d.primary {
		t.Errorf("bulk still on the call's queueing path %d", d.primary)
	}
}

// Make-before-break puts real-time on two paths at once. Bulk should take
// the third rather than land on the path that is carrying the overlap,
// which exists precisely to protect the call through the handover.
func TestBulkAvoidsTheHandoverOverlapPath(t *testing.T) {
	w := newWorld(t, path(0, 400), path(1, 400), path(2, 400))
	w.tick(w.c.PromoteIntervals + 5)

	w.set(0, func(p *pathMetric) { p.recentLoss = 40; p.burstRatio = 20 })

	var d *decision
	for i := 0; i < 50; i++ {
		if d = w.tick(1); d.switching {
			break
		}
	}
	if !d.switching {
		t.Fatal("a collapsed primary never started a handover")
	}

	rt := txSet(d)
	if len(d.txBulk) != 1 {
		t.Fatalf("bulk on %v during a handover, want exactly one path", d.txBulk)
	}
	if rt[d.txBulk[0]] {
		t.Errorf("bulk on path %d, which is carrying the handover overlap %v", d.txBulk[0], d.tx)
	}
}

// When real-time is duplicated onto everything, there is no path free of
// it and bulk shares the primary. Steering it onto a duplication target
// would put the download on the very link insuring the call.
func TestBulkSharesThePrimaryWhenRealTimeUsesEveryPath(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 60))
	w.c.DuplicateMode = config.DuplicateAlways
	w.s.cfg = config.NewHolder(w.c)

	d := w.tick(w.c.PromoteIntervals + 5)
	if len(d.tx) != 2 {
		t.Fatalf("real-time on %v, want both paths in always mode", d.tx)
	}
	if len(d.txBulk) != 1 || d.txBulk[0] != d.primary {
		t.Errorf("bulk on %v with real-time everywhere, want the primary", d.txBulk)
	}
}

// The forest canopy case from scope-v1.md: an hour of intermittent
// obstruction, real-time pinned to the good link, "use Starlink only for
// bulk, where intermittency costs nothing". An unstable path is still an
// eligible target, which is why no stability test guards the choice.
func TestBulkUsesAFlappingPathRatherThanTheCallsPath(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 60))
	w.tick(w.c.PromoteIntervals + 5)

	// Degrade path 1 without taking it down: loss enough to demote it,
	// not enough silence to make it unusable.
	w.set(1, func(p *pathMetric) { p.recentLoss = 12; p.burstRatio = 3 })
	d := w.tick(w.c.DemoteIntervals + 2)

	if w.s.machines[1].state != stateUnstable {
		t.Fatalf("path 1 is %s, wanted it demoted to unstable", w.s.machines[1].state)
	}
	if d.primary != 0 {
		t.Fatalf("primary is path %d, want the clean path 0", d.primary)
	}
	if len(d.txBulk) != 1 || d.txBulk[0] != 1 {
		t.Errorf("bulk on %v, want the flapping path 1 rather than the call's", d.txBulk)
	}
}

// Moving bulk between links reorders every TCP flow on it, and the
// receiver reads reordering as loss. A scheduler that chased the better
// link every time two scores crossed would pay for the move repeatedly in
// exactly the traffic it was trying to speed up.
func TestBulkStaysPutWhileItsPathStillWorks(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 60), path(2, 80))
	d := w.tick(w.c.PromoteIntervals + 5)

	first := d.txBulk[0]
	if first == d.primary {
		t.Fatalf("bulk started on the call's path %d", d.primary)
	}

	// Make the other spare clearly better than the one bulk is on,
	// without making bulk's path unusable.
	other := uint8(1)
	if first == 1 {
		other = 2
	}
	w.set(other, func(p *pathMetric) { p.rttMs = 5 })
	w.set(first, func(p *pathMetric) { p.rttMs = 90 })

	if d := w.tick(10); d.txBulk[0] != first {
		t.Errorf("bulk moved from path %d to %d for a better score alone", first, d.txBulk[0])
	}
}

// Blind mode sprays both classes alike: there is no measurement left to
// tell them apart with, so steering would be acting on a distinction
// nothing can currently support.
func TestBlindModeLeavesBulkOnEveryPath(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 60))
	w.tick(w.c.PromoteIntervals + 5)

	for _, id := range []uint8{0, 1} {
		w.set(id, func(p *pathMetric) {
			p.silentFor = w.c.DownSilence() * 2
			p.sentSinceHeard = uint64(w.c.DownProbePackets) * 2
		})
	}
	d := w.tick(3)

	if !d.blind {
		t.Fatal("expected blind mode with every path down")
	}
	if len(d.txBulk) != len(d.tx) {
		t.Errorf("bulk on %v and real-time on %v; blind mode sprays both alike", d.txBulk, d.tx)
	}
}

// The step 9 trap, one level worse. Below WireGuard nothing can be
// classified and every packet is ClassUnknown, which is carried as bulk.
// Steering on that would move all traffic off the best path onto the
// second best, leaving the call on the worse link and the primary
// carrying probes.
func TestBulkIsNotSteeredWithoutClassification(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 60))
	w.s.setClassifying(false)
	d := w.tick(w.c.PromoteIntervals + 5)

	if len(d.txBulk) != 1 || d.txBulk[0] != d.primary {
		t.Fatalf("bulk on %v below WireGuard, want the primary %d", d.txBulk, d.primary)
	}
	if !sameSet(w.s.txPaths(protocol.ClassUnknown), d.tx) {
		t.Errorf("unclassified traffic on %v but real-time on %v; below WireGuard they are the same packets",
			w.s.txPaths(protocol.ClassUnknown), d.tx)
	}
}

func sameSet(a, b []uint8) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[uint8]bool{}
	for _, id := range a {
		seen[id] = true
	}
	for _, id := range b {
		if !seen[id] {
			return false
		}
	}
	return true
}

// budgeted marks a path's band, which is all the scheduler reads.
func budgeted(w *world, id uint8, b usage.Band) {
	w.set(id, func(p *pathMetric) { p.budget = usage.State{Band: b, Metered: true} })
}

// Sacrifice order, first rung. A duplicate is by definition redundant, so
// cutting it costs resilience but not function - and it is the one traffic
// that doubles a link's spend to buy insurance nobody has needed yet.
func TestDuplicationStopsOnANonGreenLink(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 60))
	w.c.DuplicateMode = config.DuplicateAlways
	w.s.cfg = config.NewHolder(w.c)

	if d := w.tick(w.c.PromoteIntervals + 5); len(d.tx) != 2 {
		t.Fatalf("real-time on %v before any budget pressure, want both paths", d.tx)
	}

	budgeted(w, 1, usage.Yellow)
	d := w.tick(2)

	if len(d.tx) != 1 {
		t.Errorf("real-time on %v with the spare link yellow, want the primary alone", d.tx)
	}
	if d.tx[0] != d.primary {
		t.Errorf("real-time on path %d, want the primary %d", d.tx[0], d.primary)
	}
}

// Sacrifice order, second rung. Bulk prefers a green link when one is
// free.
func TestBulkPrefersAGreenLink(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 50), path(2, 60))
	w.tick(w.c.PromoteIntervals + 5)

	// Make every spare yellow except one, so the choice is about the band
	// rather than about the score.
	d := w.tick(1)
	for _, sc := range []uint8{0, 1, 2} {
		if sc != d.primary {
			budgeted(w, sc, usage.Yellow)
		}
	}
	green := uint8(0)
	for _, id := range []uint8{0, 1, 2} {
		if id != d.primary {
			green = id
			break
		}
	}
	w.set(green, func(p *pathMetric) { p.budget = usage.State{Band: usage.Green} })

	if d := w.tick(2); d.txBulk[0] != green {
		t.Errorf("bulk on path %d, want the green path %d", d.txBulk[0], green)
	}
}

// Being on course to exceed a cap is not the same as having spent it.
// Stalling every download for a projection would be acting on an estimate
// as though it were a fact, so a yellow link still carries bulk when
// nothing greener is free.
func TestYellowLinkStillCarriesBulkWhenNothingGreenIsFree(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 60))
	w.tick(w.c.PromoteIntervals + 5)

	budgeted(w, 0, usage.Yellow)
	budgeted(w, 1, usage.Yellow)
	d := w.tick(2)

	if len(d.txBulk) != 1 {
		t.Fatalf("bulk on %v, want exactly one path", d.txBulk)
	}
	if d.txBulk[0] == d.primary {
		t.Errorf("bulk fell back to the call's path %d when a yellow spare was free", d.primary)
	}
}

// Red is the allowance actually gone, and architecture.md reserves what
// is left for a call. Bulk never rides it.
func TestBulkNeverRidesARedLink(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 60))
	w.tick(w.c.PromoteIntervals + 5)

	d := w.tick(1)
	spare := uint8(0)
	if d.primary == 0 {
		spare = 1
	}
	budgeted(w, spare, usage.Red)

	if d := w.tick(2); d.txBulk[0] == spare {
		t.Errorf("bulk steered onto the red path %d", spare)
	}
}

// Stickiness does not outrank a spent allowance: a link that turns red
// while bulk is riding it is the case the band exists for.
func TestBulkLeavesAPathThatTurnsRed(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 50), path(2, 60))
	d := w.tick(w.c.PromoteIntervals + 5)

	on := d.txBulk[0]
	if on == d.primary {
		t.Fatalf("bulk started on the call's path %d", d.primary)
	}

	budgeted(w, on, usage.Red)
	if d := w.tick(2); d.txBulk[0] == on {
		t.Errorf("bulk stayed on path %d after it went red", on)
	}
}

// A penalty, not a veto. architecture.md wants a red link carrying
// real-time when it is the only viable path, because a working call beats
// an overage.
func TestRedLinkStillCarriesTheCallWhenItIsAllThereIs(t *testing.T) {
	w := newWorld(t, path(0, 40))
	w.tick(w.c.PromoteIntervals + 5)

	budgeted(w, 0, usage.Red)
	d := w.tick(3)

	if !d.havePrimary || d.primary != 0 {
		t.Fatalf("no primary with a red sole path; a working call beats an overage")
	}
	if len(d.tx) != 1 || d.tx[0] != 0 {
		t.Errorf("real-time on %v, want the red sole path", d.tx)
	}
}

// And the penalty is real: given a choice, the greener link wins even
// when the metered one measures better.
func TestTheGreenerLinkWinsTheCall(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 60))
	w.tick(w.c.PromoteIntervals + 5)

	// Path 0 measures better but has spent its allowance.
	budgeted(w, 0, usage.Red)
	d := w.tick(w.c.SwitchHoldIntervals + 5)

	if d.primary != 1 {
		t.Errorf("primary is path %d, want the unmetered path 1 over the red one", d.primary)
	}
}

// Stickiness holds against a better score but yields to a better band.
// Scores cross many times an hour; a band changes a handful of times a
// month and means real money.
func TestBulkMovesFromAYellowLinkToAGreenOne(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 50), path(2, 60))
	d := w.tick(w.c.PromoteIntervals + 5)

	on := d.txBulk[0]
	budgeted(w, on, usage.Yellow)

	d = w.tick(2)
	if d.txBulk[0] == on {
		t.Errorf("bulk stayed on path %d after it went yellow while a green link was free", on)
	}
	if band := w.paths[d.txBulk[0]].budget.Band; band != usage.Green {
		t.Errorf("bulk moved to a %s path, want the green one", band)
	}
}

// flowHash must be stable per flow (so a flow never splits across paths) and
// differ across flows (so flows actually spread).
func TestFlowHashStableAndDistinct(t *testing.T) {
	// minimal IPv4+TCP header: version/IHL, ..proto@9.., src@12, dst@16, ports@20
	pkt := func(sp, dp byte) []byte {
		p := make([]byte, 24)
		p[0] = 0x45 // IPv4, IHL 5
		p[9] = 6    // TCP
		copy(p[12:16], []byte{10, 0, 0, 5})
		copy(p[16:20], []byte{1, 1, 1, 1})
		p[20], p[21], p[22], p[23] = 0, sp, 0, dp
		return p
	}
	a1, a2 := flowHash(pkt(1, 80)), flowHash(pkt(1, 80))
	if a1 != a2 {
		t.Fatalf("same flow hashed differently: %d vs %d", a1, a2)
	}
	if flowHash(pkt(2, 80)) == a1 && flowHash(pkt(1, 81)) == a1 {
		t.Fatal("different flows all hash identically; no spread")
	}
	if flowHash([]byte{0x60}) != 0 { // too short / not IPv4
		t.Error("malformed packet should hash to 0")
	}
}

// txFor is what the data path actually calls: real-time duplicates across its
// whole set, while bulk and transactional each land on exactly one of the
// load-balancing paths chosen by the flow hash, and different flows use
// different paths. An empty spread set falls back to the class default.
func TestTxForSpreadsButNeverRealtime(t *testing.T) {
	s := &scheduler{}
	s.cur.Store(&decision{
		tx: []uint8{0, 1}, txBulk: []uint8{1}, txTrans: []uint8{0},
		txBulkSpread: []uint8{0, 1},
	})
	if got := s.txFor(protocol.ClassRealtime, 999); !sameSet(got, []uint8{0, 1}) {
		t.Fatalf("real-time = %v, want the full duplication set [0 1]", got)
	}
	for _, class := range []uint8{protocol.ClassBulk, protocol.ClassTransactional} {
		seen := map[uint8]bool{}
		for f := uint32(0); f < 16; f++ {
			got := s.txFor(class, f)
			if len(got) != 1 {
				t.Fatalf("class %d flow %d spread to %v, want one path", class, f, got)
			}
			seen[got[0]] = true
		}
		if len(seen) < 2 {
			t.Fatalf("class %d never used both paths: %v", class, seen)
		}
	}
	s.cur.Store(&decision{tx: []uint8{0}, txBulk: []uint8{0}, txTrans: []uint8{0}})
	if got := s.txFor(protocol.ClassBulk, 3); !sameSet(got, []uint8{0}) {
		t.Fatalf("empty spread, bulk = %v, want fallback [0]", got)
	}
}

// spreadSet is the load-balancing membership as a set, for the D-045 tests.
func spreadSet(d *decision) map[uint8]bool {
	out := map[uint8]bool{}
	for _, id := range d.txBulkSpread {
		out[id] = true
	}
	return out
}

// The regression that produced D-045, measured on a real box before it was
// written. Two links: one confirmed at 30 Mbps, one that has squeezed down to
// 636 kbps but is not losing packets and has fine jitter - so the state
// machine calls it stable, correctly, and D-044's filter let it into the
// spread as a full peer. The hash then handed it half of every download.
//
// The observed symptom was an iperf3 run that came back either 121 Mbit/s or
// 0.35 Mbit/s depending on nothing but the source port, 50/50 across eight
// flows. Stability was never the missing test; size was.
func TestSpreadExcludesAStableButTinyPath(t *testing.T) {
	w := newWorld(t, path(0, 30), path(1, 40))
	w.s.setClassifying(true)

	w.set(0, func(p *pathMetric) { p.bw = bwView{sendKbps: 800, limitKbps: 30000, haveCeiling: true} })
	w.set(1, func(p *pathMetric) { p.bw = bwView{sendKbps: 600, limitKbps: 636, haveCeiling: true} })
	d := w.tick(w.c.PromoteIntervals + 5)

	// The premise: both links are healthy. If the state machine had called
	// path 1 unstable, D-044 would already have excluded it and this test
	// would be proving nothing.
	if w.s.machines[1].state != stateStable {
		t.Fatalf("path 1 is %v, want stable - the point is that it is healthy and small",
			w.s.machines[1].state)
	}

	if spreadSet(d)[1] {
		t.Errorf("spread %v includes the 636 kbps path beside a 30 Mbps one", d.txBulkSpread)
	}
	if !spreadSet(d)[0] {
		t.Errorf("spread %v dropped the good path too", d.txBulkSpread)
	}
}

// The other half of the gate: links of comparable size must still aggregate.
// A 5 Mbps link beside a 30 Mbps one is worth having, and a fix that quietly
// turned load balancing off would pass the test above and be useless.
func TestSpreadKeepsAPathWorthAggregating(t *testing.T) {
	w := newWorld(t, path(0, 30), path(1, 40))
	w.s.setClassifying(true)

	w.set(0, func(p *pathMetric) { p.bw = bwView{sendKbps: 800, limitKbps: 30000, haveCeiling: true} })
	w.set(1, func(p *pathMetric) { p.bw = bwView{sendKbps: 600, limitKbps: 5000, haveCeiling: true} })
	d := w.tick(w.c.PromoteIntervals + 5)

	if !spreadSet(d)[0] || !spreadSet(d)[1] {
		t.Errorf("spread = %v, want both links: 5 Mbps beside 30 is worth aggregating",
			d.txBulkSpread)
	}
}

// Unknown capacity is permission, as it is everywhere else a limit is read
// (D-023). A link nobody has watched fill up must not be excluded for having
// been quiet - on a box whose links are quiet most of the time that would
// disable the spread rather than size it.
func TestSpreadAdmitsAPathWithNoMeasuredCeiling(t *testing.T) {
	w := newWorld(t, path(0, 30), path(1, 40))
	w.s.setClassifying(true)

	w.set(0, func(p *pathMetric) { p.bw = bwView{sendKbps: 800, limitKbps: 30000, haveCeiling: true} })
	w.set(1, func(p *pathMetric) { p.bw = bwView{} }) // never loaded, no opinion
	d := w.tick(w.c.PromoteIntervals + 5)

	if !spreadSet(d)[1] {
		t.Errorf("spread = %v, want the unmeasured path included: unknown is not small",
			d.txBulkSpread)
	}
}

// The invariant behind capping the share bound at 100: the best candidate is
// always 100% of itself, so no setting inside the bounds can turn a non-empty
// spread into an empty one and strand bulk on the txBulk fallback.
func TestSpreadIsNeverEmptiedByTheGate(t *testing.T) {
	w := newWorld(t, path(0, 30), path(1, 40))
	w.c.BulkSpreadMinSharePercent = config.Bounds["bulk_spread_min_share_percent"].Max
	w.s.cfg = config.NewHolder(w.c)
	w.s.setClassifying(true)

	w.set(0, func(p *pathMetric) { p.bw = bwView{sendKbps: 800, limitKbps: 30000, haveCeiling: true} })
	w.set(1, func(p *pathMetric) { p.bw = bwView{sendKbps: 600, limitKbps: 29999, haveCeiling: true} })
	d := w.tick(w.c.PromoteIntervals + 5)

	if len(d.txBulkSpread) == 0 {
		t.Fatal("the strictest legal share emptied the spread")
	}
	if !spreadSet(d)[0] {
		t.Errorf("spread = %v, want at least the largest path to survive any share",
			d.txBulkSpread)
	}
}

// The gate in isolation, including the two readings of zero that keep it from
// refusing on ignorance.
func TestUndersizedForSpread(t *testing.T) {
	c := config.Defaults() // 12%
	cases := []struct {
		name        string
		limit, best float64
		want        bool
	}{
		{"the D-045 case: 636 kbps against 30 Mbps", 636, 30000, true},
		{"a 512k standby tier against 30 Mbps", 512, 30000, true},
		{"5 Mbps against 30 Mbps is worth having", 5000, 30000, false},
		{"the best path is always 100% of itself", 30000, 30000, false},
		{"exactly at the share is not below it", 3600, 30000, false},
		{"a hair under the share is below it", 3599, 30000, true},
		{"no measured ceiling is permission", 0, 30000, false},
		{"no opinion anywhere disables the gate", 636, 0, false},
	}
	for _, tc := range cases {
		if got := undersizedForSpread(tc.limit, tc.best, c); got != tc.want {
			t.Errorf("%s: undersizedForSpread(%.0f, %.0f) = %v, want %v",
				tc.name, tc.limit, tc.best, got, tc.want)
		}
	}
}

// The link that produced D-046, reproduced from the real shape of it.
//
// The state machine reads inbound loss (pathstate.go: recentLoss) while the
// scorer reads the outbound loss the peer reports (scoreInputs: txLoss). So a
// path whose receive direction is clean is called "stable (clean)" however
// badly its send direction is failing - which is exactly how a link dropping
// 66-71% of what it was given kept its place in the load-balancing set and
// took half of every download with it.
func TestSpreadExcludesAStableButUndeliveringPath(t *testing.T) {
	w := newWorld(t, path(0, 30), path(1, 40))
	w.s.setClassifying(true)

	w.set(0, func(p *pathMetric) {
		p.haveTx, p.txLoss, p.txBurstRatio, p.rttFloorMs = true, 0, 1, 30
	})
	// Inbound clean, outbound in ruins. Nothing else says anything is wrong.
	w.set(1, func(p *pathMetric) {
		p.haveTx, p.txLoss, p.txBurstRatio, p.rttFloorMs = true, 30, 1, 40
		p.recentLoss = 0
	})
	d := w.tick(w.c.PromoteIntervals + 5)

	// The premise. If the state machine had called path 1 unstable, D-044
	// would already have excluded it and this test would prove nothing.
	if w.s.machines[1].state != stateStable {
		t.Fatalf("path 1 is %v, want stable - the whole point is that it looks fine",
			w.s.machines[1].state)
	}
	if spreadSet(d)[1] {
		t.Errorf("spread %v includes a path losing 30%% of what it is sent", d.txBulkSpread)
	}
	if !spreadSet(d)[0] {
		t.Errorf("spread %v dropped the good path too", d.txBulkSpread)
	}
}

// The other side of the gate. Ordinary cellular loss is a few percent and
// scores in the eighties - a link like that is exactly what the spread is for,
// and a fix that excluded it would have turned load balancing off.
func TestSpreadKeepsAPathWithOrdinaryCellularLoss(t *testing.T) {
	w := newWorld(t, path(0, 30), path(1, 40))
	w.s.setClassifying(true)

	w.set(0, func(p *pathMetric) {
		p.haveTx, p.txLoss, p.txBurstRatio, p.rttFloorMs = true, 0, 1, 30
	})
	w.set(1, func(p *pathMetric) {
		p.haveTx, p.txLoss, p.txBurstRatio, p.rttFloorMs = true, 3, 1, 40
	})
	d := w.tick(w.c.PromoteIntervals + 5)

	if !spreadSet(d)[0] || !spreadSet(d)[1] {
		t.Errorf("spread = %v, want both: 3%% loss is a working link", d.txBulkSpread)
	}
}

// A path can read fine at the instant it is sampled and still be unusable.
// That is how the D-046 link kept rejoining the set - it oscillated across the
// stability threshold and collected its half of the flows every time it landed
// on the good side. machine.flapping already exists to say "stop trying".
func TestSpreadExcludesAFlappingPath(t *testing.T) {
	w := newWorld(t, path(0, 30), path(1, 40))
	w.s.setClassifying(true)

	w.set(0, func(p *pathMetric) {
		p.haveTx, p.txLoss, p.txBurstRatio, p.rttFloorMs = true, 0, 1, 30
	})
	w.set(1, func(p *pathMetric) {
		p.haveTx, p.txLoss, p.txBurstRatio, p.rttFloorMs = true, 0, 1, 40
	})
	w.tick(w.c.PromoteIntervals + 5)

	// Quality is perfect; only the history is bad.
	m := w.s.machines[1]
	for i := 0; i < w.c.FlapThreshold; i++ {
		m.transitions = append(m.transitions, w.now)
	}
	d := w.tick(1)

	if spreadSet(d)[1] {
		t.Errorf("spread %v includes a flapping path", d.txBulkSpread)
	}
}

// Principle 5. When the gate leaves nothing, bulk must not stop - it falls
// back to D-033's single steered path, which is deliberately unguarded because
// a flaky link is still a better home for a download than the call's path.
func TestSpreadEmptyStillCarriesBulk(t *testing.T) {
	w := newWorld(t, path(0, 30), path(1, 40))
	w.s.setClassifying(true)

	for _, id := range []uint8{0, 1} {
		w.set(id, func(p *pathMetric) {
			p.haveTx, p.txLoss, p.txBurstRatio, p.rttFloorMs = true, 40, 1, 40
		})
	}
	d := w.tick(w.c.PromoteIntervals + 5)

	if len(d.txBulkSpread) != 0 {
		t.Fatalf("spread = %v, want empty when nothing is delivering", d.txBulkSpread)
	}
	if got := w.s.txFor(protocol.ClassBulk, 7); len(got) == 0 {
		t.Error("bulk has nowhere to go with an empty spread; it must fall back to txBulk")
	}
}

// Cost is not brokenness. The quality gate reads the raw R factor, not
// machine.score, because score folds in the metered-link surcharge - a yellow
// link that is working perfectly must still aggregate.
func TestSpreadQualityGateIgnoresTheMeteredSurcharge(t *testing.T) {
	w := newWorld(t, path(0, 30), path(1, 40))
	w.s.setClassifying(true)

	w.set(0, func(p *pathMetric) {
		p.haveTx, p.txLoss, p.txBurstRatio, p.rttFloorMs = true, 0, 1, 30
	})
	w.set(1, func(p *pathMetric) {
		p.haveTx, p.txLoss, p.txBurstRatio, p.rttFloorMs = true, 0, 1, 40
		p.budget.Band = usage.Yellow
	})
	d := w.tick(w.c.PromoteIntervals + 5)

	if !spreadSet(d)[1] {
		t.Errorf("spread = %v, want the yellow link: expensive is not broken", d.txBulkSpread)
	}
}
