package relay

import "testing"

// The case this exists for: two copies of one packet, one delivered.
func TestSecondCopyIsDropped(t *testing.T) {
	w := newDedupWindow()

	if !w.accept(100) {
		t.Fatal("first copy was dropped")
	}
	if w.accept(100) {
		t.Error("second copy of the same packet was delivered")
	}
}

// Ordinary traffic with no duplication must pass untouched, including
// with gaps - probes and reports consume sequence numbers of their own,
// so the data stream the window sees is never contiguous.
func TestUnduplicatedTrafficPassesIncludingGaps(t *testing.T) {
	w := newDedupWindow()

	for _, seq := range []uint32{5, 6, 9, 10, 40, 41, 500} {
		if !w.accept(seq) {
			t.Errorf("sequence %d was dropped as a duplicate", seq)
		}
	}
}

// Paths differ in latency, so the copy that wins is not always the one
// sent first and packets arrive out of order. Reordering is not
// duplication and must not be treated as it.
func TestReorderingIsNotDuplication(t *testing.T) {
	w := newDedupWindow()

	w.accept(100)
	for _, seq := range []uint32{99, 98, 97, 96} {
		if !w.accept(seq) {
			t.Errorf("late arrival %d was dropped; it had not been seen", seq)
		}
	}
	// And each of those is still deduplicated on its own.
	if w.accept(98) {
		t.Error("a duplicate of a late arrival was delivered")
	}
}

// Fail open. This is deduplication, not replay protection: a packet older
// than the window is one the mechanism can no longer speak to, and the
// cost of guessing wrong is a lost packet rather than a wasted copy.
func TestPacketOlderThanTheWindowIsDelivered(t *testing.T) {
	w := newDedupWindow()

	w.accept(1_000_000)
	if !w.accept(1_000_000 - dedupBits - 1) {
		t.Error("a packet older than the window was dropped; dedup must fail open")
	}
}

// Advancing past the window clears it, or a much later sequence would
// land on a stale bit and be mistaken for a duplicate.
func TestAdvancingPastTheWindowDoesNotStrandStaleBits(t *testing.T) {
	w := newDedupWindow()

	w.accept(10)
	w.accept(10 + dedupBits*3) // far beyond the window

	// 10 maps to the same slot as 10+dedupBits*3 does not, but any
	// sequence whose slot collides with an old one must still pass.
	for i := uint32(1); i < 200; i++ {
		seq := 10 + dedupBits*3 + i
		if !w.accept(seq) {
			t.Fatalf("sequence %d was dropped after a long jump forward", seq)
		}
	}
}

// The slots between an old top and a new one get reused, so they have to
// be cleared as the window advances.
func TestSlotsAreClearedAsTheWindowAdvances(t *testing.T) {
	w := newDedupWindow()

	// Fill a stretch, then walk far enough forward that those sequences'
	// slots come round again.
	for seq := uint32(1); seq <= 100; seq++ {
		w.accept(seq)
	}
	for seq := uint32(101); seq <= dedupBits+150; seq++ {
		if !w.accept(seq) {
			t.Fatalf("sequence %d was dropped; its slot held a stale bit", seq)
		}
	}
}

// The counter is 32 bits and wraps after about four billion packets.
// Serial arithmetic makes that an ordinary advance; a plain comparison
// would read it as a jump four billion packets backwards and drop
// everything after it.
func TestSequenceWraparoundIsAnOrdinaryAdvance(t *testing.T) {
	w := newDedupWindow()

	near := ^uint32(0) - 2 // three short of wrapping

	// Well past the wrap, not merely over it. A comparison that reads the
	// wrap as a jump backwards still delivers the next few packets - it
	// just stops advancing the top, and the window quietly stops sliding.
	// The damage shows up thousands of packets later, when sequences
	// start landing on slots nothing has cleared.
	for i := uint32(0); i < dedupBits*2; i++ {
		seq := near + i
		if !w.accept(seq) {
			t.Fatalf("sequence %d (%d past the wraparound) was dropped", seq, i)
		}
	}

	// And dedup still works on the far side of it.
	if w.accept(near + dedupBits) {
		t.Error("a duplicate after the wraparound was delivered")
	}
}

// The window is on the receive path of every packet the daemon carries,
// so it has to be safe under concurrent use.
func TestWindowIsSafeConcurrently(t *testing.T) {
	w := newDedupWindow()
	done := make(chan struct{})

	for g := 0; g < 4; g++ {
		go func(base uint32) {
			for i := uint32(0); i < 5000; i++ {
				w.accept(base + i)
			}
			done <- struct{}{}
		}(uint32(g) * 10000)
	}
	for i := 0; i < 4; i++ {
		<-done
	}
}

// The case the slot clearing actually exists for, which a contiguous walk
// never reaches.
//
// When the window jumps forward it skips a range of sequences that have
// not arrived. Those slots still hold the bits of the sequences one full
// window earlier, which map to exactly the same place. If they are not
// cleared, a packet from the skipped range arriving late - the ordinary
// consequence of two paths with different latency - reads as a duplicate
// of something long gone and is thrown away.
func TestLateArrivalInASkippedRangeIsNotMistakenForADuplicate(t *testing.T) {
	w := newDedupWindow()

	// Run past one full window, so every slot holds a real bit.
	var top uint32
	for seq := uint32(1); seq <= dedupBits+500; seq++ {
		w.accept(seq)
		top = seq
	}

	// Jump forward, skipping 299 sequences.
	if !w.accept(top + 300) {
		t.Fatal("the jump forward was itself dropped")
	}

	// One of the skipped sequences now arrives late, still inside the
	// window. Its slot is shared with a sequence one window back, which
	// was delivered.
	if !w.accept(top + 100) {
		t.Error("a late packet from a skipped range was dropped as a duplicate" +
			" of a sequence one window earlier")
	}
	// And it is still deduplicated on its own account.
	if w.accept(top + 100) {
		t.Error("the second copy of that late packet was delivered")
	}
}
