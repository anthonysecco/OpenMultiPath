package relay

import (
	"strings"
	"testing"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

// cascadeWorld is a world whose peer can resequence, so the cascade runs.
func cascadeWorld(t *testing.T, paths ...pathMetric) *world {
	t.Helper()
	w := newWorld(t, paths...)
	w.s.peerResequences = func() bool { return true }
	w.full = map[uint8]bool{}
	w.s.hasRoom = func(id uint8) bool { return !w.full[id] }
	return w
}

// reported is a path whose send direction the peer is reporting on.
func reported(id uint8, rttMs float64) pathMetric {
	p := path(id, rttMs)
	p.haveTx = true
	p.rttFloorMs = rttMs
	p.txBurstRatio = 1
	p.sendKbps = 50_000
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

// Unshaped, or shaped with room, the first path takes everything - S3's "bulk
// always on the higher-latency link until it is full".
func TestCascadeFirstPathTakesAllBulkUntilItIsFull(t *testing.T) {
	w := cascadeWorld(t, reported(0, 40), reported(1, 90))
	w.settle()
	placed, dropped := w.sendBulk(500, 1200)
	if dropped != 0 || placed[1] != 500 {
		t.Errorf("placed %v dropped %d, want all 500 on the slower path 1", placed, dropped)
	}
}

// A path whose shaper is backed up spills onto the next in the order (D-055),
// and one that drains takes bulk again.
func TestCascadeSpillsWhenTheFirstPathsShaperIsFull(t *testing.T) {
	w := cascadeWorld(t, reported(0, 40), reported(1, 90))
	w.settle()

	w.full[1] = true
	placed, dropped := w.sendBulk(300, 1250)
	if placed[0] != 300 || dropped != 0 {
		t.Errorf("placed %v dropped %d with path 1 full, want all 300 spilled onto path 0", placed, dropped)
	}

	w.full[1] = false
	if placed, _ = w.sendBulk(300, 1250); placed[1] != 300 {
		t.Errorf("placed %v once path 1 drained, want it taking bulk again", placed)
	}
}

// With every path backed up, bulk goes to the first path in the order and is
// never dropped here: the shaper's own queue is where a sender finds the
// aggregate's limit.
func TestCascadeOverflowsToTheFirstPathAndNeverDrops(t *testing.T) {
	w := cascadeWorld(t, reported(0, 40), reported(1, 90))
	w.settle()
	w.full[0], w.full[1] = true, true
	before := w.s.overflowed.Load()
	placed, dropped := w.sendBulk(200, 1250)
	if dropped != 0 || placed[1] != 200 {
		t.Errorf("placed %v dropped %d with every path full, want all 200 on the first path 1", placed, dropped)
	}
	if got := w.s.overflowed.Load() - before; got != 200 {
		t.Errorf("overflowed counted %d, want 200", got)
	}
}

// Each member carries the speed its shaper holds it to, for the log and the
// interface. Unmeasured is unshaped.
func TestCascadeMembersCarryTheirShapedSpeed(t *testing.T) {
	w := cascadeWorld(t, reported(0, 40), reported(1, 90))
	w.set(1, func(p *pathMetric) { p.shapedKbps = 9_500 })
	d := w.settle()
	if m, _ := memberOf(d, 1); m.shapedKbps != 9_500 {
		t.Errorf("path 1 member shaped %.0f kbps, want 9500", m.shapedKbps)
	}
	if m, _ := memberOf(d, 0); m.shapedKbps != 0 {
		t.Errorf("unmeasured path 0 member shaped %.0f kbps, want 0", m.shapedKbps)
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

// Real-time is untouched by the cascade: duplicated as ever, never dropped,
// even with every path's shaper backed up.
func TestCascadeNeverPlacesRealtime(t *testing.T) {
	w := cascadeWorld(t, reported(0, 40))
	w.settle()
	w.full[0] = true
	for i := 0; i < 200; i++ {
		if tx, ok := w.s.txForPacket(protocol.ClassRealtime, uint32(i), 200); !ok || len(tx) == 0 {
			t.Fatal("real-time packet withheld by the cascade")
		}
	}
	if !w.s.admitAndPlace(protocol.ClassRealtime) {
		t.Error("real-time withheld")
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
	w.set(0, func(p *pathMetric) { p.shapedKbps = 55_000 })
	w.set(1, func(p *pathMetric) { p.shapedKbps = 3_000 })
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
	var dropped int
	for i := 0; i < 10; i++ {
		for j := 0; j < 50; j++ { // a call at 50 packets a second
			w.s.txForPacket(protocol.ClassRealtime, 99, 200)
		}
		placed, dr := w.sendBulk(500, 1250)
		dropped += dr
		if placed[0] != 500 {
			t.Fatalf("placed %v beside a call, want all 500 bulk packets on the only path", placed)
		}
		w.tick(1)
	}
	if dropped != 0 {
		t.Errorf("dropped %d bulk packets beside a call", dropped)
	}
}
