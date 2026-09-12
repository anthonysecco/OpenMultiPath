package relay

import (
	"strings"
	"testing"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

// cascadeWorld is a world whose peer can resequence, so the cascade runs.
func cascadeWorld(t *testing.T, paths ...pathMetric) *world {
	t.Helper()
	w := newWorld(t, paths...)
	w.s.peerResequences = func() bool { return true }
	w.s.clockFn = func() time.Duration { return w.now }
	return w
}

// reported is a path whose send direction the peer is reporting on, which is
// what the cascade's controller acts on.
func reported(id uint8, rttMs float64) pathMetric {
	p := path(id, rttMs)
	p.haveTx = true
	p.rttFloorMs = rttMs
	p.txBurstRatio = 1
	// Busy enough that its reports are measurements rather than noise; see
	// the thin-load guard in capCtl.update.
	p.bw.sendKbps = 50_000
	return p
}

// settle brings every path to stable.
func (w *world) settle() *decision { return w.tick(w.c.PromoteIntervals + 5) }

// sendBulk pushes n bulk packets of size bytes through the data path's
// placement and counts where they went.
func (w *world) sendBulk(n, size int) (placed map[uint8]int, dropped int) {
	placed = map[uint8]int{}
	for i := 0; i < n; i++ {
		tx, ok := w.s.txForPacket(protocol.ClassBulk, uint32(i), size)
		if !ok {
			dropped++
			continue
		}
		for _, id := range tx {
			placed[id]++
		}
	}
	return placed, dropped
}

// pumpTick offers demandKbps of bulk spread evenly across one evaluation
// interval, the way a download actually arrives, and then evaluates. Sending
// a burst at one instant would never let a token bucket refill.
func (w *world) pumpTick(demandKbps float64) (*decision, map[uint8]int, int) {
	const steps = 20
	slice := w.c.EvalInterval() / steps
	perSlice := int(demandKbps*125*slice.Seconds()/1250) + 1
	placed, dropped := map[uint8]int{}, 0
	start := w.now
	for i := 0; i < steps; i++ {
		w.now += slice
		p, d := w.sendBulk(perSlice, 1250)
		for id, n := range p {
			placed[id] += n
		}
		dropped += d
	}
	w.now = start // tick advances the clock itself
	return w.tick(1), placed, dropped
}

func ids(d *decision) []uint8 {
	out := make([]uint8, len(d.cascade))
	for i, m := range d.cascade {
		out[i] = m.id
	}
	return out
}

func sameOrder(a, b []uint8) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func memberOf(d *decision, id uint8) (cascadeMember, bool) {
	for _, m := range d.cascade {
		if m.id == id {
			return m, true
		}
	}
	return cascadeMember{}, false
}

// Spreading a flow into a receiver that cannot reorder it is what collapsed
// D-044's first live test. Toward a version 2 peer, bulk stays per flow.
func TestCascadeInactiveTowardAPeerThatCannotResequence(t *testing.T) {
	w := cascadeWorld(t, path(0, 40), path(1, 80))
	w.s.peerResequences = func() bool { return false }
	d := w.settle()
	if d.cascadeOn {
		t.Fatal("cascade ran against a peer that cannot resequence")
	}
	if !strings.Contains(d.cascadeWhy, "version") {
		t.Errorf("cascadeWhy = %q, want it to name the wire version", d.cascadeWhy)
	}
	tx, ok := w.s.txForPacket(protocol.ClassBulk, 7, 1200)
	if !ok || !sameSet(tx, w.s.txFor(protocol.ClassBulk, 7)) {
		t.Errorf("bulk placed on %v (ok=%v), want v0.1's per-flow %v", tx, ok, w.s.txFor(protocol.ClassBulk, 7))
	}
}

// The trap D-031 and D-033 both fell into: below WireGuard everything is
// unclassified, and pacing "bulk" would pace the call.
func TestCascadeInactiveWithoutClassification(t *testing.T) {
	w := cascadeWorld(t, path(0, 40), path(1, 80))
	w.s.setClassifying(false)
	if d := w.settle(); d.cascadeOn {
		t.Error("cascade ran with no classifier")
	}
}

// Blind mode sprays everything everywhere; there is nothing to pace on.
func TestCascadeInactiveInBlindMode(t *testing.T) {
	w := cascadeWorld(t, path(0, 40), path(1, 80))
	w.settle()
	for _, id := range []uint8{0, 1} {
		w.set(id, func(p *pathMetric) {
			p.silentFor = w.c.DownSilence() * 2
			p.sentSinceHeard = uint64(w.c.DownProbePackets) * 2
		})
	}
	d := w.tick(3)
	if !d.blind {
		t.Fatal("expected blind mode")
	}
	if d.cascadeOn {
		t.Error("cascade ran in blind mode")
	}
	if _, ok := w.s.txForPacket(protocol.ClassBulk, 1, 1200); !ok {
		t.Error("bulk dropped in blind mode")
	}
}

// The kill switch is v0.1 exactly, D-031's gate included.
func TestFlowModeIsVersionZeroPointOne(t *testing.T) {
	w := cascadeWorld(t, path(0, 40))
	w.c.BulkScheduler = config.BulkFlow
	w.settle()
	if d := w.s.current(); d.cascadeOn {
		t.Fatal("cascade ran with bulk_scheduler set to flow")
	}
	w.set(0, func(p *pathMetric) {
		p.haveTx = true
		p.txQueueMs = float64(w.c.AdmissionQueueDelayMs) * 2
	})
	if d := w.tick(1); !d.withholdBulk {
		t.Error("flow mode lost D-031's gate; the kill switch must restore v0.1")
	}
	for flow := uint32(0); flow < 20; flow++ {
		tx, ok := w.s.txForPacket(protocol.ClassTransactional, flow, 500)
		if !ok || !sameSet(tx, w.s.txFor(protocol.ClassTransactional, flow)) {
			t.Fatalf("flow mode placed transactional on %v, v0.1 on %v", tx, w.s.txFor(protocol.ClassTransactional, flow))
		}
	}
}

// S3 and S5: slowest path first, measured on outbound latency, and the call's
// path last whatever its latency.
func TestCascadeFillsSlowestFirstAndTheCallsPathLast(t *testing.T) {
	w := cascadeWorld(t, path(0, 40), path(1, 60), path(2, 100))
	d := w.settle()
	if !d.cascadeOn {
		t.Fatalf("cascade inactive: %s", d.cascadeWhy)
	}
	if d.primary != 0 {
		t.Fatalf("primary = %d, want 0", d.primary)
	}
	if got, want := ids(d), []uint8{2, 1, 0}; !sameOrder(got, want) {
		t.Errorf("fill order %v, want %v", got, want)
	}
	if m, _ := memberOf(d, 0); !m.protected {
		t.Error("the call's path is not marked protected")
	}
	if m, _ := memberOf(d, 2); m.protected {
		t.Error("a bulk-only path is marked protected")
	}
}

// Two links a few milliseconds apart must not trade places every evaluation,
// and a real difference must win only once it has lasted.
func TestCascadeOrderHasHysteresis(t *testing.T) {
	w := cascadeWorld(t, path(0, 30), path(1, 80), path(2, 84))
	d := w.settle()
	if got := ids(d); !sameOrder(got, []uint8{2, 1, 0}) {
		t.Fatalf("initial order %v, want [2 1 0]", got)
	}

	// Path 1 becomes slower, but only by a couple of milliseconds one way.
	w.set(1, func(p *pathMetric) { p.rttMs = 90 })
	if d = w.tick(20); !sameOrder(ids(d), []uint8{2, 1, 0}) {
		t.Errorf("order changed to %v inside the hysteresis margin", ids(d))
	}

	// Now clearly slower.
	w.set(1, func(p *pathMetric) { p.rttMs = 130 })
	if d = w.tick(cascadeSwapTicks - 1); !sameOrder(ids(d), []uint8{2, 1, 0}) {
		t.Errorf("order changed to %v before the swap had lasted", ids(d))
	}
	if d = w.tick(2); !sameOrder(ids(d), []uint8{1, 2, 0}) {
		t.Errorf("order %v, want [1 2 0] once path 1 has stayed slower", ids(d))
	}
}

// Uncapped, the first path takes everything - which is S3's "bulk always on
// the higher-latency link until congestion is detected".
func TestCascadeFirstPathTakesAllBulkUntilItCongests(t *testing.T) {
	w := cascadeWorld(t, reported(0, 40), reported(1, 90))
	w.settle()
	placed, dropped := w.sendBulk(500, 1200)
	if dropped != 0 || placed[1] != 500 {
		t.Errorf("placed %v dropped %d, want all 500 on the slower path 1", placed, dropped)
	}
}

// Congestion on the first path caps it, and the overflow spills onto the next.
// Nothing is ever dropped: past every allowance bulk goes to the least-queued
// path.
func TestCascadeSpillsOnlyOnceTheFirstPathCongests(t *testing.T) {
	w := cascadeWorld(t, reported(0, 40), reported(1, 90))
	w.settle()

	w.sendBulk(2000, 1250) // ~50 Mbps over one evaluation, all onto path 1
	w.set(1, func(p *pathMetric) { p.txStandingMs = float64(w.c.CascadeQueueTargetMs) * 3 })
	w.tick(cascadeConfirmIntervals - 1)
	w.sendBulk(2000, 1250)
	d := w.tick(1)
	m, ok := memberOf(d, 1)
	if !ok || m.capKbps == 0 {
		t.Fatalf("path 1 not capped after congesting: %+v", d.cascade)
	}
	if m.capKbps > m.sentKbps {
		t.Errorf("cap %.0f kbps above the %.0f kbps that congested it", m.capKbps, m.sentKbps)
	}

	// The queue drains; the cut stands for now, and bulk past it spills.
	w.set(1, func(p *pathMetric) { p.txStandingMs = 0 })
	w.tick(1)
	w.now += 10 * time.Millisecond // a little refill
	placed, dropped := w.sendBulk(2000, 1250)
	if placed[1] == 0 || placed[0] == 0 {
		t.Errorf("placed %v: want path 1 up to its cap and the rest spilling onto path 0", placed)
	}
	if dropped != 0 {
		t.Errorf("dropped %d; the cascade never drops bulk", dropped)
	}
}

// D-046's link lost two thirds of its traffic and never queued. Loss alone
// must cap a path.
func TestCascadeLossAloneCapsAPath(t *testing.T) {
	w := cascadeWorld(t, reported(0, 40), reported(1, 90))
	w.settle()
	w.sendBulk(1000, 1250)
	w.set(1, func(p *pathMetric) { p.txShortLoss = float64(w.c.CascadeLossPercent) * 2 })
	w.tick(cascadeConfirmIntervals - 1)
	w.sendBulk(1000, 1250)
	d := w.tick(1)
	if m, _ := memberOf(d, 1); m.capKbps == 0 {
		t.Error("a path losing twice the threshold with no queue was not capped")
	}
}

// Random radio loss below the threshold must not ratchet a healthy link down,
// which is how cubic collapsed the uplink (D-041).
func TestCascadeOrdinaryLossDoesNotCap(t *testing.T) {
	w := cascadeWorld(t, reported(0, 40), reported(1, 90))
	w.settle()
	w.sendBulk(1000, 1250)
	w.set(1, func(p *pathMetric) { p.txShortLoss = float64(w.c.CascadeLossPercent) / 2 })
	d := w.tick(10)
	if m, _ := memberOf(d, 1); m.capKbps != 0 {
		t.Errorf("path capped at %.0f kbps for loss below the threshold", m.capKbps)
	}
}

// Nothing reported, nothing throttled - admission control's answer, for the
// same reason.
func TestCascadeDoesNotThrottleWithoutEvidence(t *testing.T) {
	w := cascadeWorld(t, path(0, 40))
	w.settle()
	w.set(0, func(p *pathMetric) { p.txStandingMs = 500; p.txShortLoss = 50 })
	d := w.tick(5)
	if m, _ := memberOf(d, 0); m.capKbps != 0 {
		t.Errorf("capped at %.0f kbps on figures nobody reported", m.capKbps)
	}
	if _, dropped := w.sendBulk(100, 1250); dropped != 0 {
		t.Errorf("dropped %d with no send-direction evidence", dropped)
	}
}

// The call's path is cut by its own congestion exactly like any other path,
// against the same target - and real-time is never paced.
func TestCascadeCallsPathIsCutLikeAnyOtherPath(t *testing.T) {
	w := cascadeWorld(t, reported(0, 40))
	w.settle()

	w.set(0, func(p *pathMetric) { p.txStandingMs = float64(w.c.CascadeQueueTargetMs) * 4 })
	var last float64
	for i := 0; i < 40; i++ {
		w.sendBulk(1000, 1250)
		d := w.tick(1)
		m, ok := memberOf(d, 0)
		if !ok || !m.protected {
			t.Fatalf("the call's path is not in the cascade: %+v", d.cascade)
		}
		if i >= cascadeConfirmIntervals && m.capKbps == 0 {
			t.Fatalf("evaluation %d: uncapped with its queue at four times the target", i)
		}
		if i >= cascadeConfirmIntervals && last != 0 && m.capKbps > last {
			t.Fatalf("allowance rose from %.0f to %.0f kbps while the queue stood", last, m.capKbps)
		}
		last = m.capKbps
	}
	if !w.s.admitAndPlace(protocol.ClassRealtime) {
		t.Error("real-time withheld; it is never paced")
	}
}

// Cut at once, grown back only after a clean run: the same asymmetry on the
// call's path as anywhere else, and no slower.
func TestCascadeCallsPathRecoversAfterStayingClear(t *testing.T) {
	w := cascadeWorld(t, reported(0, 40))
	w.settle()
	w.sendBulk(1000, 1250)
	w.set(0, func(p *pathMetric) { p.txStandingMs = float64(w.c.CascadeQueueTargetMs) * 2 })
	w.tick(cascadeConfirmIntervals - 1)
	w.sendBulk(1000, 1250)
	d := w.tick(1)
	capAfterCut := func(d *decision) float64 { m, _ := memberOf(d, 0); return m.capKbps }
	cut := capAfterCut(d)
	if cut == 0 {
		t.Fatal("no cut to recover from")
	}

	w.set(0, func(p *pathMetric) { p.txStandingMs = 0 })
	need := w.c.CascadeRecoverIntervals
	for i := 0; i < need-1; i++ {
		if d, _, _ = w.pumpTick(1_000_000); capAfterCut(d) != cut && capAfterCut(d) > cut {
			t.Fatalf("allowance grew from %.0f to %.0f after %d clean evaluations, want none before %d",
				cut, capAfterCut(d), i+1, need)
		}
	}
	for i := 0; i < 3; i++ {
		d, _, _ = w.pumpTick(1_000_000)
	}
	if got := capAfterCut(d); got != 0 && got <= cut {
		t.Errorf("allowance never grew after staying clear and in use (still %.0f kbps)", got)
	}
}

// A cap nobody is pushing against is not evidence of headroom.
func TestCascadeCapGrowsOnlyWhileInUse(t *testing.T) {
	w := cascadeWorld(t, reported(0, 40), reported(1, 90))
	w.settle()
	w.sendBulk(1000, 1250)
	w.set(1, func(p *pathMetric) { p.txStandingMs = float64(w.c.CascadeQueueTargetMs) * 2 })
	w.tick(cascadeConfirmIntervals - 1)
	w.sendBulk(1000, 1250)
	d := w.tick(1)
	m, _ := memberOf(d, 1)
	cut := m.capKbps
	w.set(1, func(p *pathMetric) { p.txStandingMs = 0 })
	d = w.tick(w.c.CascadeRecoverIntervals * 4) // clean, but no bulk sent
	if m, _ = memberOf(d, 1); m.capKbps != cut {
		t.Errorf("idle cap grew from %.0f to %.0f kbps", cut, m.capKbps)
	}
}

// A path too far behind the call's path for the resequencer to wait on is not
// spread onto.
func TestCascadeDeltaGateExcludesAPathTooFarBehind(t *testing.T) {
	w := cascadeWorld(t, path(0, 40), path(1, 90), path(2, 800))
	d := w.settle()
	if _, ok := memberOf(d, 2); ok {
		t.Errorf("path 2, %d ms behind, is in the cascade %v", 380, ids(d))
	}
	if _, ok := memberOf(d, 1); !ok {
		t.Errorf("path 1 missing from the cascade %v", ids(d))
	}
}

// Forest canopy, per packet. An unstable link that is not flapping still takes
// bulk first; a flapping one does not, because a spread flow stalls on every
// burst it loses.
func TestCascadeUsesAnUnstablePathButNotAFlappingOne(t *testing.T) {
	w := cascadeWorld(t, path(0, 40), path(1, 90))
	w.settle()
	w.set(1, func(p *pathMetric) { p.recentLoss = float64(w.c.UnstableLossPercent) * 3 })
	d := w.tick(w.c.DemoteIntervals + 2)
	if w.s.machines[1].state != stateUnstable {
		t.Fatalf("path 1 is %v, want unstable", w.s.machines[1].state)
	}
	if got := ids(d); !sameOrder(got, []uint8{1, 0}) {
		t.Errorf("fill order %v, want the unstable path 1 first and the call's path 0 last", got)
	}

	// Now make it flap.
	for i := 0; i < w.c.FlapThreshold+2; i++ {
		w.set(1, func(p *pathMetric) { p.recentLoss = 0 })
		w.tick(w.c.PromoteIntervals + 1)
		w.set(1, func(p *pathMetric) { p.recentLoss = float64(w.c.UnstableLossPercent) * 3 })
		w.tick(w.c.DemoteIntervals + 1)
	}
	if !w.s.machines[1].flapping(w.now, w.c) {
		t.Fatal("path 1 is not flapping")
	}
	if _, ok := memberOf(w.s.current(), 1); ok {
		t.Errorf("a flapping path is in the cascade %v", ids(w.s.current()))
	}
}

// S3: page loads stay on the low-latency link. Transactional goes back to the
// primary alone while the cascade runs.
func TestCascadeKeepsTransactionalOnTheCallsPath(t *testing.T) {
	w := cascadeWorld(t, path(0, 40), path(1, 90))
	d := w.settle()
	for flow := uint32(0); flow < 50; flow++ {
		tx, ok := w.s.txForPacket(protocol.ClassTransactional, flow, 400)
		if !ok || len(tx) != 1 || tx[0] != d.primary {
			t.Fatalf("transactional flow %d on %v (ok=%v), want the primary %d alone", flow, tx, ok, d.primary)
		}
	}
}

// Real-time is untouched by the cascade: duplicated as ever, never dropped.
func TestCascadeNeverPacesRealtime(t *testing.T) {
	w := cascadeWorld(t, reported(0, 40))
	w.settle()
	w.set(0, func(p *pathMetric) { p.txStandingMs = 1000 })
	for i := 0; i < 20; i++ {
		w.sendBulk(1000, 1250)
		w.tick(1)
	}
	for i := 0; i < 200; i++ {
		if tx, ok := w.s.txForPacket(protocol.ClassRealtime, uint32(i), 200); !ok || len(tx) == 0 {
			t.Fatal("real-time packet withheld by the cascade")
		}
	}
}

// admitAndPlace is the whole ingress decision the data path makes for one
// packet of a class.
func (s *scheduler) admitAndPlace(class uint8) bool {
	if !s.admit(class) {
		return false
	}
	_, ok := s.txForPacket(class, 1, 200)
	return ok
}

// A cut made while almost no bulk was on the path - the queue was a page load
// or a download still classed transactional - is not evidence against bulk.
// Once the path is clean it goes back to uncapped instead of crawling up from
// the floor.
func TestCascadeBlamelessCutIsForgotten(t *testing.T) {
	w := cascadeWorld(t, reported(0, 40), reported(1, 90))
	w.settle()
	w.set(1, func(p *pathMetric) { p.txStandingMs = float64(w.c.CascadeQueueTargetMs) * 3 })
	d := w.tick(cascadeConfirmIntervals) // no bulk sent at all
	if m, _ := memberOf(d, 1); m.capKbps == 0 {
		t.Fatal("no cut to forget")
	}
	w.set(1, func(p *pathMetric) { p.txStandingMs = 0 })
	d = w.tick(w.c.CascadeRecoverIntervals + 1)
	if m, _ := memberOf(d, 1); m.capKbps != 0 {
		t.Errorf("blameless cut still in force at %.0f kbps after the path stayed clean", m.capKbps)
	}
}

// Once a path has congested, its allowance is held near what actually arrived,
// so a sender's excursions above it spill rather than queue - the difference
// between BBR aggregating and not.
func TestCascadeAllowanceTracksWhatArrivedAfterCongestion(t *testing.T) {
	w := cascadeWorld(t, reported(0, 40), reported(1, 90))
	w.settle()
	w.pumpTick(50_000)
	w.set(1, func(p *pathMetric) { p.txStandingMs = float64(w.c.CascadeQueueTargetMs) * 3 })
	w.pumpTick(50_000)
	w.pumpTick(50_000)
	// The link now carries 20 Mbit whatever it is offered, and says so.
	w.set(1, func(p *pathMetric) { p.txStandingMs = 0; p.txRxKbps = 20_000 })
	var d *decision
	for i := 0; i < 30; i++ {
		d, _, _ = w.pumpTick(50_000)
	}
	m, _ := memberOf(d, 1)
	if m.capKbps == 0 || m.capKbps > 20_000*cascadePeakHeadroom*1.01 {
		t.Errorf("allowance %.0f kbps on a path delivering 20000; want at most %.0f", m.capKbps, 20_000*cascadePeakHeadroom)
	}
}

// The receive rate the peer reports wins when it is lower: that is the link
// being full while its buffer hides it.
func TestBulkDeliveredPrefersWhatArrived(t *testing.T) {
	m := reported(0, 40)
	m.bw.sendKbps = 30_000
	m.txRxKbps = 21_000
	if got := bulkDeliveredKbps(m, 29_000); got < 19_900 || got > 20_100 {
		t.Errorf("delivered %.0f kbps, want the 21000 received less the 1000 of other traffic", got)
	}
	m.txRxKbps = 0
	if got := bulkDeliveredKbps(m, 29_000); got != 29_000 {
		t.Errorf("delivered %.0f kbps with no receive rate, want the sent figure", got)
	}
}

// A path carrying next to nothing reports single samples. Read as congestion
// they cut idle links to the floor on the vehicle, where they never then
// carried enough to be measured properly.
func TestCascadeIgnoresQueueReadingsOnAnIdlePath(t *testing.T) {
	w := cascadeWorld(t, reported(0, 40), reported(1, 90))
	w.set(1, func(p *pathMetric) { p.bw.sendKbps = 20 })
	w.settle()
	w.set(1, func(p *pathMetric) { p.txStandingMs = 65; p.txShortLoss = 30 })
	d := w.tick(10)
	if m, _ := memberOf(d, 1); m.capKbps != 0 {
		t.Errorf("idle path capped at %.0f kbps on single-sample readings", m.capKbps)
	}
}

// One reading over the line is not congestion; two running are.
func TestCascadeNeedsTheQueueToHoldBeforeCutting(t *testing.T) {
	w := cascadeWorld(t, reported(0, 40), reported(1, 90))
	w.settle()
	w.set(1, func(p *pathMetric) { p.txStandingMs = 200 })
	w.sendBulk(1000, 1250)
	d := w.tick(1)
	if m, _ := memberOf(d, 1); m.capKbps != 0 {
		t.Errorf("cut to %.0f kbps on a single spike", m.capKbps)
	}
	w.set(1, func(p *pathMetric) { p.txStandingMs = 0 })
	w.sendBulk(1000, 1250)
	d = w.tick(1)
	w.set(1, func(p *pathMetric) { p.txStandingMs = 200 })
	w.sendBulk(1000, 1250)
	d = w.tick(1)
	if m, _ := memberOf(d, 1); m.capKbps != 0 {
		t.Errorf("cut to %.0f kbps on two spikes that did not run together", m.capKbps)
	}
}

// The canopy fallback is for a link that comes and goes, not one losing half
// of what it is given: spread per packet, that stalls every flow it touches.
func TestCascadeCanopyFallbackRefusesALinkThatIsNotDelivering(t *testing.T) {
	w := cascadeWorld(t, reported(0, 40), reported(1, 90))
	w.settle()
	w.set(1, func(p *pathMetric) { p.txLoss = 50; p.recentLoss = 50 })
	d := w.tick(w.c.DemoteIntervals + 2)
	if _, ok := memberOf(d, 1); ok {
		t.Errorf("a link losing half its traffic is in the cascade %v", ids(d))
	}
}

// A link a twentieth the size of the call's path is not filled first: every
// flow would crawl at its rate before reaching the big link. The size bar
// includes the call's path.
func TestCascadeSkipsALinkTooSmallBesideTheCallsPath(t *testing.T) {
	w := cascadeWorld(t, reported(0, 40), reported(1, 90))
	w.set(0, func(p *pathMetric) { p.bw.limitKbps = 55_000 })
	w.set(1, func(p *pathMetric) { p.bw.limitKbps = 3_000 })
	d := w.settle()
	if _, ok := memberOf(d, 1); ok {
		t.Errorf("a 3 Mbit link is in the cascade ahead of a 55 Mbit call's path: %v", ids(d))
	}
}

// The owner's rule: real-time on a path changes where that path sits in the
// order and nothing else. With a call on the only path, bulk still takes the
// whole path and nothing is dropped.
func TestRealtimeOnAPathNeverThrottlesBulk(t *testing.T) {
	w := cascadeWorld(t, reported(0, 40))
	w.settle()
	w.set(0, func(p *pathMetric) { p.txStandingMs = 2 }) // a healthy path
	var d *decision
	var dropped int
	for i := 0; i < 10; i++ {
		for j := 0; j < 50; j++ { // a call at 50 packets a second
			w.s.txForPacket(protocol.ClassRealtime, 99, 200)
		}
		var dr int
		d, _, dr = w.pumpTick(50_000)
		dropped += dr
	}
	if m, _ := memberOf(d, 0); m.capKbps != 0 {
		t.Errorf("bulk capped at %.0f kbps on a healthy path because a call shares it", m.capKbps)
	}
	if dropped != 0 {
		t.Errorf("dropped %d bulk packets beside a call", dropped)
	}
}
