package relay

import (
	"testing"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

// sendTrans pushes n packets of one transactional flow through the data path's
// placement and counts where they went.
func (w *world) sendTrans(flow uint32, n int) map[uint8]int {
	placed := map[uint8]int{}
	for i := 0; i < n; i++ {
		tx, ok := w.s.txForPacket(protocol.ClassTransactional, flow, 1200)
		if !ok || len(tx) != 1 {
			placed[255]++ // not one path; no test expects this, so onlyOn fails
			continue
		}
		placed[tx[0]]++
	}
	return placed
}

// onlyOn reports whether every packet counted went to one path.
func onlyOn(placed map[uint8]int, id uint8) bool {
	return len(placed) == 1 && placed[id] > 0
}

// holdTicks is enough evaluations for a moved flow's hold to run out.
func (w *world) holdTicks() int { return int(transMoveHold/w.c.EvalInterval()) + 1 }

// The field case: a transactional aggregate outgrows the primary's
// transactional band. The flow moves whole onto the next best path, and stays
// there once the primary drains - moving back would be a second reordering for
// nothing.
func TestTransactionalFlowMovesWholeOffAFullPrimaryAndStays(t *testing.T) {
	w := cascadeWorld(t, path(0, 40), path(1, 60), path(2, 100))
	d := w.settle()
	if d.primary != 0 {
		t.Fatalf("primary = %d, want 0", d.primary)
	}
	if got := w.sendTrans(7, 20); !onlyOn(got, 0) {
		t.Fatalf("flow placed %v with room everywhere, want the primary 0 alone", got)
	}

	w.transFull[0] = true
	if got := w.sendTrans(7, 20); !onlyOn(got, 1) {
		t.Errorf("flow placed %v with the primary full, want all of it on the next best path 1", got)
	}
	if n := w.s.transMoved.Load(); n != 1 {
		t.Errorf("counted %d moves, want 1: a flow moves once, not once a packet", n)
	}

	w.transFull[0] = false
	w.tick(w.holdTicks())
	if got := w.sendTrans(7, 20); !onlyOn(got, 1) {
		t.Errorf("flow placed %v once the primary drained, want it left on path 1", got)
	}
}

// Other flows are untouched: only a flow that sends while its own path is full
// moves, and a new flow starts on the primary whenever it has room.
func TestTransactionalMovesOnlyFlowsWhosePathIsFull(t *testing.T) {
	w := cascadeWorld(t, path(0, 40), path(1, 60))
	w.settle()
	w.sendTrans(1, 1)
	w.sendTrans(2, 1)

	w.transFull[0] = true
	w.sendTrans(1, 1) // flow 1 moves to path 1
	w.transFull[0] = false

	if got := w.sendTrans(2, 10); !onlyOn(got, 0) {
		t.Errorf("flow 2 placed %v, want it left on the primary 0", got)
	}
	if got := w.sendTrans(3, 10); !onlyOn(got, 0) {
		t.Errorf("a new flow placed %v with the primary free again, want the primary 0", got)
	}
}

// A new flow arriving while the primary is full starts where there is room.
// That is placement, not a move.
func TestNewTransactionalFlowStartsWhereThereIsRoom(t *testing.T) {
	w := cascadeWorld(t, path(0, 40), path(1, 60))
	w.settle()
	w.transFull[0] = true
	if got := w.sendTrans(9, 10); !onlyOn(got, 1) {
		t.Errorf("new flow placed %v with the primary full, want path 1", got)
	}
	if n := w.s.transMoved.Load(); n != 0 {
		t.Errorf("counted %d moves for a flow that was only ever on one path", n)
	}
}

// With every path full a move buys a reordering and no room, so the flow stays
// where it is.
func TestTransactionalStaysPutWhenEveryPathIsFull(t *testing.T) {
	w := cascadeWorld(t, path(0, 40), path(1, 60))
	w.settle()
	w.sendTrans(3, 1)
	w.transFull[0], w.transFull[1] = true, true
	if got := w.sendTrans(3, 20); !onlyOn(got, 0) {
		t.Errorf("flow placed %v with every path full, want it left on the primary 0", got)
	}
	if n := w.s.transMoved.Load(); n != 0 {
		t.Errorf("counted %d moves with nowhere to move to", n)
	}
}

// A flow too big for either of two links must not bounce between them as each
// drains behind it. It holds its new path, and only after the hold follows the
// room.
func TestMovedTransactionalFlowHoldsBeforeMovingAgain(t *testing.T) {
	w := cascadeWorld(t, path(0, 40), path(1, 60))
	w.settle()
	w.sendTrans(4, 1)
	w.transFull[0] = true
	w.sendTrans(4, 1) // onto path 1

	// Path 1 fills behind it and the primary drains.
	w.transFull[0], w.transFull[1] = false, true
	w.tick(1)
	if got := w.sendTrans(4, 20); !onlyOn(got, 1) {
		t.Errorf("flow placed %v inside its hold, want it held on path 1", got)
	}
	w.tick(w.holdTicks())
	if got := w.sendTrans(4, 20); !onlyOn(got, 0) {
		t.Errorf("flow placed %v after its hold with path 1 still full, want the primary 0", got)
	}
	if n := w.s.transMoved.Load(); n != 2 {
		t.Errorf("counted %d moves, want 2", n)
	}
}

// A path that leaves the order - here, gone down - gives its flows back at
// once, hold or not.
func TestTransactionalFlowLeavesAPathThatGoesDown(t *testing.T) {
	w := cascadeWorld(t, path(0, 40), path(1, 60))
	w.settle()
	w.sendTrans(5, 1)
	w.transFull[0] = true
	w.sendTrans(5, 1) // onto path 1, held
	w.transFull[0] = false

	w.set(1, func(p *pathMetric) { p.silentFor = w.c.DownSilence() * 2; p.sentSinceHeard = 1000 })
	d := w.tick(2)
	if w.s.machines[1].state != stateDown {
		t.Fatalf("path 1 is %v, want down", w.s.machines[1].state)
	}
	if len(d.transOrder) > 1 {
		t.Fatalf("transactional order %v still offers more than the primary", d.transOrder)
	}
	if got := w.sendTrans(5, 5); !onlyOn(got, 0) {
		t.Errorf("flow placed %v with its path down, want the primary 0", got)
	}
}

// The next best is the scheduler's own ranking: lowest latency among healthy
// links, whatever their ids.
func TestTransactionalOrderIsThePrimaryThenTheRanking(t *testing.T) {
	w := cascadeWorld(t, path(0, 100), path(1, 40), path(2, 60))
	d := w.settle()
	if got, want := d.transOrder, []uint8{1, 2, 0}; !sameOrder(got, want) {
		t.Errorf("transactional order %v, want %v", got, want)
	}
}

// Bulk backing up a path is not transactional running out of room: the
// transactional band drains ahead of it (D-060).
func TestBulkBacklogDoesNotMoveTransactional(t *testing.T) {
	w := cascadeWorld(t, path(0, 40), path(1, 60))
	w.settle()
	w.full[0] = true
	if got := w.sendTrans(6, 20); !onlyOn(got, 0) {
		t.Errorf("flow placed %v with only bulk backed up, want the primary 0", got)
	}
}

// A flow that moves is one that filled a path, so a link too small beside the
// best is not somewhere to move it (D-045), and neither is one losing half of
// what it is given (D-046).
func TestTransactionalDoesNotMoveOntoASmallOrLossyLink(t *testing.T) {
	w := cascadeWorld(t, reported(0, 40), reported(1, 60), reported(2, 90))
	w.set(0, func(p *pathMetric) { p.shapedKbps = 55_000 })
	w.set(1, func(p *pathMetric) { p.shapedKbps = 3_000 })
	w.set(2, func(p *pathMetric) { p.shapedKbps = 50_000 })
	d := w.settle()
	if got, want := d.transOrder, []uint8{0, 2}; !sameOrder(got, want) {
		t.Errorf("transactional order %v, want %v without the 3 Mbit link", got, want)
	}

	w.set(2, func(p *pathMetric) { p.txLoss = 50; p.recentLoss = 50 })
	d = w.tick(w.c.DemoteIntervals + 2)
	if got, want := d.transOrder, []uint8{0}; !sameOrder(got, want) {
		t.Errorf("transactional order %v, want %v without the lossy link", got, want)
	}
}

// But the small link as primary is exactly the field case: it is always in the
// order, first, and flows leave it for the big one.
func TestTransactionalLeavesASmallPrimaryForABigLink(t *testing.T) {
	w := cascadeWorld(t, reported(0, 40), reported(1, 60))
	w.set(0, func(p *pathMetric) { p.shapedKbps = 562 })
	w.set(1, func(p *pathMetric) { p.shapedKbps = 76_000 })
	d := w.settle()
	if d.primary != 0 {
		t.Fatalf("primary = %d, want the small low-latency path 0", d.primary)
	}
	w.sendTrans(8, 1)
	w.transFull[0] = true
	if got := w.sendTrans(8, 20); !onlyOn(got, 1) {
		t.Errorf("flow placed %v with the small primary full, want the big path 1", got)
	}
}

// Flow mode is v0.1 exactly: transactional is spread per flow there, and none
// of this runs.
func TestTransactionalMigrationIsCascadeModeOnly(t *testing.T) {
	w := cascadeWorld(t, path(0, 40), path(1, 60))
	w.c.BulkScheduler = config.BulkFlow
	w.s.cfg.Set(w.c)
	d := w.settle()
	if d.cascadeOn || len(d.transOrder) != 0 {
		t.Fatalf("cascade on %v, transactional order %v in flow mode", d.cascadeOn, d.transOrder)
	}
	w.transFull[0] = true
	for flow := uint32(0); flow < 20; flow++ {
		w.s.txForPacket(protocol.ClassTransactional, flow, 1200)
	}
	if n := w.s.transMoved.Load(); n != 0 || len(w.s.transFlows) != 0 {
		t.Errorf("flow mode moved %d flows and remembered %d", n, len(w.s.transFlows))
	}
}

// Unclassified packets have no flow to move and queue in bulk's band, so they
// stay on the primary.
func TestUnknownIsNotMovedWithTransactional(t *testing.T) {
	w := cascadeWorld(t, path(0, 40), path(1, 60))
	d := w.settle()
	w.transFull[0] = true
	tx, ok := w.s.txForPacket(protocol.ClassUnknown, 11, 200)
	if !ok || len(tx) != 1 || tx[0] != d.primary {
		t.Errorf("unclassified placed on %v (ok=%v), want the primary %d", tx, ok, d.primary)
	}
}

// A flow idle past the timeout is forgotten, so a reused port pair starts on
// the primary rather than inheriting another conversation's move.
func TestIdleTransactionalFlowIsForgotten(t *testing.T) {
	w := cascadeWorld(t, path(0, 40), path(1, 60))
	w.settle()
	w.sendTrans(12, 1)
	w.transFull[0] = true
	w.sendTrans(12, 1) // onto path 1
	w.transFull[0] = false

	idle := w.s.current().transIdle
	w.tick(int(idle/w.c.EvalInterval()) + 2)
	if got := w.sendTrans(12, 5); !onlyOn(got, 0) {
		t.Errorf("a flow idle past %v placed %v, want it placed afresh on the primary 0", idle, got)
	}
	if len(w.s.transFlows) != 1 {
		t.Errorf("flow table holds %d entries after the sweep, want just the one re-placed", len(w.s.transFlows))
	}
}
