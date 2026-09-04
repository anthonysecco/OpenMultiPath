package relay

import (
	"testing"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
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

// Anything not positively identified as real-time is carried as bulk -
// D-027's asymmetry applied where it costs something.
func TestUnknownClassIsCarriedAsBulk(t *testing.T) {
	w := newWorld(t, path(0, 40), path(1, 60))
	w.c.DuplicateMode = config.DuplicateAlways
	w.tick(w.c.PromoteIntervals + 5)

	unknown := w.s.txPaths(protocol.ClassUnknown)
	bulk := w.s.txPaths(protocol.ClassBulk)
	realtime := w.s.txPaths(protocol.ClassRealtime)

	if len(unknown) != len(bulk) {
		t.Errorf("unclassified traffic took %v, bulk took %v; they must match", unknown, bulk)
	}
	if len(unknown) >= len(realtime) {
		t.Errorf("unclassified traffic took %v, as many paths as real-time's %v;"+
			" an unidentified download must not be duplicated", unknown, realtime)
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
