package relay

import "sync"

// dedupWindow drops the second copy of a duplicated packet.
//
// Duplication is the point of D-022: real-time goes out two paths so that
// losing one costs nothing. Both copies then arrive, and exactly one of
// them should be delivered.
//
// Below WireGuard that happened for free. The daemon relayed ciphertext
// into a WireGuard interface, and WireGuard's own replay window discarded
// the redundant copy - which is what the comment in initiator.go used to
// say. D-020 moved the daemon above WireGuard, where it writes plaintext
// into a TUN and there is no replay window underneath any more, so every
// duplicated packet was being delivered twice. Measured on the running
// pair: twenty packets sent, forty delivered.
//
// The two copies carry the same GlobalSeq - the sender allocates it once
// per packet and stamps every copy with it - which is what makes this
// possible at all.
//
// # Fail open, not closed
//
// This is deduplication, not replay protection, and the difference decides
// the one interesting case: a packet older than the window. A security
// filter drops it, because an attacker replaying old traffic is the threat
// it exists for. Here the threat is a wasted copy and the cost of being
// wrong is a lost packet, so anything the window can no longer speak to is
// delivered. Principle 5 in miniature: when the mechanism stops being able
// to tell, carry the traffic.
//
// The window is sized so that case is rare rather than relied upon. Two
// copies of a packet are sent at the same moment and separated only by the
// difference in path latency - a few hundred milliseconds at worst - so a
// window covering tens of thousands of packets is many times wider than it
// needs to be, and costs 8 KB.
type dedupWindow struct {
	mu   sync.Mutex
	bits []uint64
	top  uint32
	seen bool
}

// dedupBits is the width of the window, in packets.
//
// It was 4096, "four seconds at a thousand packets a second". v0.2 spreads
// bulk per packet, and a bulk flow on two links runs at tens of thousands of
// packets a second: a duplicated real-time copy arriving 200 ms behind its
// twin is then six thousand sequences back, past a 4096-packet window, and
// would fail open into being delivered twice. 65536 covers two seconds at
// thirty thousand packets a second.
const dedupBits = 65536

func newDedupWindow() *dedupWindow {
	return &dedupWindow{bits: make([]uint64, dedupBits/64)}
}

func (w *dedupWindow) mark(seq uint32)  { w.bits[(seq/64)%uint32(len(w.bits))] |= 1 << (seq % 64) }
func (w *dedupWindow) clear(seq uint32) { w.bits[(seq/64)%uint32(len(w.bits))] &^= 1 << (seq % 64) }
func (w *dedupWindow) isSet(seq uint32) bool {
	return w.bits[(seq/64)%uint32(len(w.bits))]&(1<<(seq%64)) != 0
}

// reset forgets everything, so the next packet starts the window afresh.
// The session calls it when the peer restarts: the peer's global sequence
// has started again from zero, and a window still holding the old counter
// would either fail open on every packet (old top far ahead) or drop the
// new packets as copies of old ones (old top close behind).
func (w *dedupWindow) reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := range w.bits {
		w.bits[i] = 0
	}
	w.seen = false
}

// reseedLocked starts the window again at seq.
func (w *dedupWindow) reseedLocked(seq uint32) {
	for i := range w.bits {
		w.bits[i] = 0
	}
	w.top = seq
	w.mark(seq)
}

// accept reports whether this packet should be delivered. A false means it
// is a copy of one already delivered.
func (w *dedupWindow) accept(seq uint32) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.seen {
		w.seen, w.top = true, seq
		w.mark(seq)
		return true
	}

	// Serial arithmetic rather than a plain comparison, so the counter
	// wrapping past four billion packets is an ordinary advance rather
	// than a sudden four-billion-packet jump backwards.
	switch d := int32(seq - w.top); {
	case d > 0:
		// Newer than anything seen. The slots between the old top and
		// the new one are about to be reused by sequences that have not
		// arrived, so they have to be cleared or a future packet would
		// be mistaken for a duplicate of a long-gone one.
		if int(d) >= dedupBits {
			for i := range w.bits {
				w.bits[i] = 0
			}
		} else {
			for s := w.top + 1; s != seq; s++ {
				w.clear(s)
			}
		}
		w.mark(seq)
		w.top = seq
		return true

	case int(-d) >= dedupBits:
		// Older than the window can speak to. Deliver it - see the
		// fail-open note above - and start the window again from here.
		//
		// Delivering alone was not enough. A peer that restarts counts
		// from zero again, and every packet it sends reads as older than
		// the old top: with nothing to move the top back, the window
		// failed open for good and every duplicated packet was delivered
		// twice until the new counter caught the old one up. On the real
		// pair that was home delivering each of a call's uplink packets
		// twice after a deploy restarted it two seconds ahead of the
		// vehicle. The session resets the window when it sees a restart
		// (reset); this is what keeps a restart the detector misses from
		// costing the same. A genuinely ancient straggler re-seeds it too,
		// which costs at most a few copies delivered twice while the
		// window re-learns - the direction this mechanism is allowed to
		// err in.
		w.reseedLocked(seq)
		return true

	default:
		if w.isSet(seq) {
			return false
		}
		w.mark(seq)
		return true
	}
}
