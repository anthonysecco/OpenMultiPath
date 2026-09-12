package relay

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

// reseqRig drives a resequencer with a clock the test holds.
type reseqRig struct {
	t   *testing.T
	now time.Duration
	r   *resequencer
	out []uint32 // the sequence number each delivered payload carried
}

func newReseqRig(t *testing.T, hold time.Duration) *reseqRig {
	g := &reseqRig{t: t, now: time.Millisecond} // zero reads as "never" in the path bookkeeping
	g.r = newResequencer(func(p []byte) error {
		g.out = append(g.out, binary.BigEndian.Uint32(p))
		return nil
	}, func() time.Duration { return g.now })
	g.r.setHold(hold)
	return g
}

// push sends sequence seq of bucket on a path, with the payload naming the
// sequence so delivery order can be read back.
func (g *reseqRig) push(path uint8, bucket uint16, seq uint32) {
	var p [8]byte
	binary.BigEndian.PutUint32(p[:], seq)
	g.r.push(path, bucket, seq, p[:])
}

func (g *reseqRig) advance(d time.Duration) {
	g.now += d
	g.r.sweepOnce()
}

func (g *reseqRig) want(seqs ...uint32) {
	g.t.Helper()
	if len(g.out) != len(seqs) {
		g.t.Fatalf("delivered %v, want %v", g.out, seqs)
	}
	for i := range seqs {
		if g.out[i] != seqs[i] {
			g.t.Fatalf("delivered %v, want %v", g.out, seqs)
		}
	}
}

func TestResequencerPassesInOrderStraightThrough(t *testing.T) {
	g := newReseqRig(t, 50*time.Millisecond)
	for s := uint32(100); s < 110; s++ {
		g.push(0, 1, s)
	}
	g.want(100, 101, 102, 103, 104, 105, 106, 107, 108, 109)
	if g.r.reordered.Load() != 0 || g.r.buffered != 0 {
		t.Errorf("in-order traffic was held: reordered=%d buffered=%d", g.r.reordered.Load(), g.r.buffered)
	}
}

// The case it exists for: two paths, the fast one delivering ahead of a
// packet still in flight on the slow one.
func TestResequencerReordersAcrossPaths(t *testing.T) {
	g := newReseqRig(t, 100*time.Millisecond)
	g.push(0, 1, 0) // slow path starts the flow
	g.push(1, 1, 2) // fast path is ahead
	g.push(1, 1, 3) //
	g.advance(20 * time.Millisecond)
	g.want(0) // 2 and 3 held for 1
	g.push(0, 1, 1)
	g.want(0, 1, 2, 3)
	if g.r.timedOut.Load() != 0 || g.r.lostSkipped.Load() != 0 {
		t.Errorf("a gap that filled in time was given up on")
	}
}

// A gap that never fills costs at most the hold, and what was waiting is
// delivered rather than dropped.
func TestResequencerGivesUpOnAGapAtTheHold(t *testing.T) {
	g := newReseqRig(t, 50*time.Millisecond)
	g.push(0, 1, 0)
	g.push(1, 1, 5) // path 1 delivers 5; path 0 still owes 1..4
	g.push(1, 1, 6)
	g.advance(40 * time.Millisecond)
	g.want(0)
	g.advance(20 * time.Millisecond)
	g.want(0, 5, 6)
	if g.r.timedOut.Load() == 0 {
		t.Error("timed-out gap not counted")
	}
}

// Fail open: a packet whose gap was already given up on is delivered late,
// not lost.
func TestResequencerDeliversALatePacket(t *testing.T) {
	g := newReseqRig(t, 50*time.Millisecond)
	g.push(0, 1, 0)
	g.push(1, 1, 2)
	g.advance(60 * time.Millisecond)
	g.want(0, 2)
	g.push(0, 1, 1)
	g.want(0, 2, 1)
	if g.r.late.Load() != 1 {
		t.Errorf("late = %d, want 1", g.r.late.Load())
	}
}

// Paths do not reorder their own packets, so once every path carrying the
// flow has delivered past a gap the gap is lost, and waiting out the hold
// for it would stall the flow for nothing.
func TestResequencerSkipsAGapEveryPathHasPassed(t *testing.T) {
	g := newReseqRig(t, time.Second)
	g.push(0, 1, 0)
	g.push(1, 1, 1)
	g.push(1, 1, 3) // path 1 has passed 2
	g.want(0, 1)
	g.push(0, 1, 4) // and now so has path 0: 2 is lost
	g.want(0, 1, 3, 4)
	if g.r.lostSkipped.Load() != 1 {
		t.Errorf("lostSkipped = %d, want 1", g.r.lostSkipped.Load())
	}
}

// A flow on one path only reorders through loss, and the one path has
// always passed the gap: nothing waits.
func TestResequencerNeverHoldsASinglePathFlow(t *testing.T) {
	g := newReseqRig(t, time.Second)
	g.push(0, 1, 0)
	g.push(0, 1, 2) // 1 lost
	g.want(0, 2)
}

// A path that stopped carrying the flow long ago is not waited on.
func TestResequencerIgnoresAPathThatStoppedCarryingTheFlow(t *testing.T) {
	g := newReseqRig(t, 10*time.Second)
	g.push(0, 1, 0)
	g.advance(reseqPathActive + time.Millisecond)
	g.push(1, 1, 1)
	g.push(1, 1, 3)
	g.want(0, 1, 3)
}

// A gap in one flow must not hold up another. This is the reason for
// sequencing per flow bucket rather than on GlobalSeq.
func TestResequencerBucketsAreIndependent(t *testing.T) {
	g := newReseqRig(t, time.Second)
	g.push(0, 1, 0)
	g.push(1, 1, 2) // bucket 1 has a gap at 1
	g.push(0, 1, 0+0)
	g.out = nil
	g.push(0, 7, 50)
	g.push(0, 7, 51)
	g.want(50, 51)
}

// The field wraps every million packets, which at bulk rates is under two
// minutes. Stepping over the wrap by a handful of packets is not enough to
// catch a comparison that stops the window sliding: run thousands past it.
func TestResequencerSurvivesSequenceWrap(t *testing.T) {
	g := newReseqRig(t, time.Second)
	start := uint32(protocol.FlowSeqMask - 2000)
	var want []uint32
	for i := uint32(0); i < 6000; i++ {
		s := (start + i) & protocol.FlowSeqMask
		want = append(want, s)
	}
	// The flow starts in order - its first packet is what the bucket starts
	// from - and then every pair arrives swapped across two paths.
	g.push(0, 3, want[0])
	i := 1
	for ; i+1 < len(want); i += 2 {
		g.push(1, 3, want[i+1])
		g.push(0, 3, want[i])
	}
	for ; i < len(want); i++ {
		g.push(0, 3, want[i])
	}
	g.want(want...)
	if g.r.timedOut.Load()+g.r.lostSkipped.Load()+g.r.late.Load()+g.r.forced.Load() != 0 {
		t.Errorf("wrap produced skips: timedOut=%d lost=%d late=%d forced=%d",
			g.r.timedOut.Load(), g.r.lostSkipped.Load(), g.r.late.Load(), g.r.forced.Load())
	}
}

// A restarted sender starts its counters from zero. Reading its first packet
// as ancient would leave the bucket delivering everything late forever.
func TestResequencerFollowsASenderRestart(t *testing.T) {
	g := newReseqRig(t, time.Second)
	g.push(0, 1, 400_000)
	g.push(0, 1, 400_001)
	g.push(0, 1, 0)
	g.push(0, 1, 1)
	g.want(400_000, 400_001, 0, 1)
	if g.r.late.Load() != 0 {
		t.Errorf("restart read as late packets")
	}
}

// Past the memory bound the oldest gap is skipped. Nothing is dropped.
func TestResequencerMemoryBoundSkipsButNeverDrops(t *testing.T) {
	g := newReseqRig(t, time.Hour)
	total := 0
	for b := uint16(0); int(b)*(reseqWindow-10) < reseqMaxBuffered+5000; b++ {
		g.push(0, b, 0)
		g.push(1, b, 1) // keep path 1 behind so no gap reads as passed
		for s := uint32(3); s < reseqWindow-10; s++ {
			g.push(0, b, s)
		}
		total += reseqWindow - 10 - 1
	}
	if g.r.buffered > reseqMaxBuffered {
		t.Errorf("buffered %d, over the bound %d", g.r.buffered, reseqMaxBuffered)
	}
	if g.r.forced.Load() == 0 {
		t.Error("memory bound never forced a gap")
	}
	g.r.reset()
	if len(g.out) != total {
		t.Errorf("delivered %d of %d packets; the bound must never drop one", len(g.out), total)
	}
}

// A gap so far behind the window that the packet cannot be held forces the
// gap, and the packet is still delivered.
func TestResequencerFarAheadForcesTheGap(t *testing.T) {
	g := newReseqRig(t, 50*time.Millisecond)
	g.push(0, 1, 0)
	g.push(1, 1, 1)
	g.push(0, 1, 1+reseqWindow+5)
	if g.r.forced.Load() == 0 {
		t.Error("a packet beyond the window did not force the gap")
	}
	if g.r.buffered > 1 {
		t.Errorf("buffered %d after forcing, want the one packet at most", g.r.buffered)
	}
	g.advance(60 * time.Millisecond)
	if len(g.out) != 3 {
		t.Errorf("delivered %v, want all three once the hold ran out", g.out)
	}
}

func BenchmarkResequencerReordered(b *testing.B) {
	r := newResequencer(func([]byte) error { return nil }, func() time.Duration { return 0 })
	payload := make([]byte, 1300)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := uint32(i)
		// Pairs swapped across two paths: every other packet is held.
		if i%2 == 0 {
			r.push(1, 9, (s+1)&protocol.FlowSeqMask, payload)
		} else {
			r.push(0, 9, (s-1)&protocol.FlowSeqMask, payload)
		}
	}
}

// A flow first spread onto two paths: the fast path delivers ahead before the
// slow path has delivered anything for this flow. The slow path is carrying
// other bulk, so the gap is still in flight on it and must be waited for, not
// declared lost.
func TestResequencerWaitsForASlowPathNewToTheFlow(t *testing.T) {
	g := newReseqRig(t, time.Second)
	g.push(0, 9, 500) // path 0 is carrying another flow
	g.push(1, 1, 0)
	g.push(1, 1, 2) // 1 is on path 0, which has not delivered for bucket 1 yet
	g.want(500, 0)
	g.push(0, 1, 1)
	g.want(500, 0, 1, 2)
	if g.r.lostSkipped.Load() != 0 {
		t.Error("an in-flight packet on a path new to the flow was declared lost")
	}
}

// Past its first second a flow is judged on its own paths only, or every loss
// in a flow placed on one path would wait out the hold for a path that will
// never carry it.
func TestResequencerOldFlowIgnoresPathsThatNeverCarriedIt(t *testing.T) {
	g := newReseqRig(t, time.Hour)
	g.push(1, 1, 0)
	g.advance(reseqPathActive + time.Millisecond)
	g.push(0, 9, 500) // path 0 active, but never for bucket 1
	g.push(1, 1, 1)
	g.push(1, 1, 3) // 2 lost on path 1
	g.want(0, 500, 1, 3)
}

// The hold follows what gaps actually take to fill, not only what the path
// delays predict. The prediction underestimates whenever echoes come back on
// a faster path than they went out on.
func TestResequencerHoldFollowsObservedGaps(t *testing.T) {
	g := newReseqRig(t, 0)
	g.r.setPredictedHold(10*time.Millisecond, 200*time.Millisecond)
	g.push(0, 1, 0)
	g.push(1, 1, 2)
	g.now += 30 * time.Millisecond
	g.push(0, 1, 1) // the gap took 30 ms
	if h := g.r.holdFor(); h < 37*time.Millisecond {
		t.Errorf("hold %v after a 30 ms gap, want at least %v", h, time.Duration(float64(30*time.Millisecond)*reseqGapHeadroom))
	}
	g.now += 5 * reseqGapWindow
	g.r.setPredictedHold(10*time.Millisecond, 200*time.Millisecond)
	if h := g.r.holdFor(); h != 10*time.Millisecond {
		t.Errorf("hold %v long after the last slow gap, want the 10 ms prediction", h)
	}
}
