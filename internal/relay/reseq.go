package relay

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
	"github.com/anthonysecco/OpenMultiPath/internal/state"
)

// resequencer puts a bulk flow that the far end spread across several paths
// back in order before it is delivered (v0.2-design.md, section 7).
//
// v0.2 sends bulk per packet: one flow's packets leave on whichever path has
// room, and paths differ in latency, so they arrive out of order. TCP reads
// reordering as loss and retransmits into a link that was never short of
// anything, which is how D-044's first live test collapsed a download to
// 4 Mbps. So the receiver holds a packet that arrives ahead of a gap until the
// gap fills - and gives up on the gap if it does not.
//
// # What it orders by
//
// Not GlobalSeq, which counts every packet of every class: a lost real-time
// packet would leave a gap in it that bulk waited out, and one loss in one
// download would stall every other download too. Each bulk packet instead
// carries a sequence within a flow bucket - the sender's hash of the flow -
// so a gap holds up only the flow it belongs to, and a flow that happens to
// share a bucket with another shares its sequence space, which costs a
// little waiting and nothing in correctness.
//
// # It never drops a packet
//
// A gap that is not filled within the hold is skipped: what is waiting is
// delivered and the missing packet is left to TCP, which was always going to
// have to resend it if it was really lost. A packet that turns up after its
// gap was skipped is delivered anyway, late. That is D-038's fail-open rule
// and principle 5: when the mechanism can no longer tell, carry the traffic.
// This is a bounded hold, not a queue, so D-002 stands.
//
// # Most gaps are not waited out
//
// A real loss would otherwise cost a full hold, every time, for the whole
// flow - and a lossy link loses often. But paths do not reorder their own
// packets, so a gap is certainly lost once every path carrying the flow has
// delivered something after it. That is checked on every arrival, and it
// turns most losses into a wait no longer than the next packet on the slower
// path. The hold is only the backstop for a path that went quiet.
type resequencer struct {
	// write delivers a payload, in order. It is called with mu held, which
	// is what makes the order real: two paths' receive goroutines would
	// otherwise interleave their writes.
	write func([]byte) error

	// now is the session clock.
	now func() time.Duration

	mu       sync.Mutex
	buckets  [protocol.FlowBuckets]*reseqBucket
	waiting  map[uint16]*reseqBucket // buckets holding packets, for the sweep
	buffered int

	// hold is how long a gap is waited for, in nanoseconds: the larger of
	// what the path delays predict (session.updateHold) and what gaps have
	// actually been taking to fill (observedGap), capped.
	hold      atomic.Int64
	predicted atomic.Int64
	maxHold   atomic.Int64

	// The observed side: the longest a gap took to fill, over the current
	// and previous observation windows. Guarded by mu.
	gapCur, gapPrev time.Duration
	gapWindowAt     time.Duration

	pool sync.Pool

	// pathSeen is when each path last delivered any spread bulk at all, and
	// maxPath the highest path id seen, so the loss check can ask about
	// paths that have not yet carried a particular flow. See skipPassedGaps.
	pathSeen [256]time.Duration
	maxPath  int

	delivered     atomic.Uint64 // every payload handed on
	reordered     atomic.Uint64 // arrived ahead of a gap and was held
	late          atomic.Uint64 // arrived after its gap had been given up on
	lostSkipped   atomic.Uint64 // gaps given up on because every path had passed them
	timedOut      atomic.Uint64 // gaps given up on because the hold ran out
	forced        atomic.Uint64 // gaps given up on to stay inside the memory bound
	senderResets  atomic.Uint64 // sequence jumps read as the sender having restarted
	writeFailures atomic.Uint64
}

// reseqWindow is how far ahead of a gap one bucket will hold, in packets. A
// hundred megabit flow on links 200 ms apart is about two thousand packets
// deep; anything further ahead forces the gap to be skipped.
const reseqWindow = 4096

// reseqMaxBuffered bounds what every bucket together may hold, about 32 MB
// of pooled buffers. Past it the oldest gap is skipped - never a packet
// dropped.
const reseqMaxBuffered = 16384

// reseqRestartJump is a sequence distance too large to be reordering. The
// sender's counters start from zero when it restarts, and a bucket that
// read the first packet after that as ancient would never order again.
const reseqRestartJump = 1 << 18

// reseqIdle is how long a bucket is kept with nothing arriving. Long enough
// to bridge a pause in a download, short enough that a new flow landing in
// the bucket later starts clean.
const reseqIdle = 30 * time.Second

// reseqPathActive is how recently a path must have carried a bucket to count
// when deciding that every path has passed a gap. A path that stopped
// carrying the flow cannot still be delivering the missing packet much
// beyond the hold.
const reseqPathActive = time.Second

// reseqSweep is how often held gaps are checked against the hold.
const reseqSweep = 5 * time.Millisecond

// reseqDefaultHold is the hold before anything has been measured, and
// reseqDefaultMaxHold its cap before the settings say otherwise.
const (
	reseqDefaultHold    = 50 * time.Millisecond
	reseqDefaultMaxHold = 200 * time.Millisecond
)

// reseqGapWindow is how long an observed gap keeps the hold up. Two windows
// are held, so a slow path's delay is forgotten two to four seconds after it
// stops showing.
const reseqGapWindow = 2 * time.Second

// reseqGapHeadroom is what the observed gap is multiplied by to give a hold:
// a gap that took 30 ms last time will take a little longer some time soon.
const reseqGapHeadroom = 1.25

// reseqMarks is how many paths one bucket remembers.
const reseqMarks = 4

type reseqBucket struct {
	id       uint16
	started  bool
	next     uint32 // the sequence expected next
	lastSeen time.Duration
	startAt  time.Duration // when this flow's sequence was picked up

	// ring holds packets that arrived ahead of next, at (head + distance
	// ahead) modulo its length. Allocated on the first reordering and kept
	// while the bucket is in use.
	ring     []heldPkt
	head     int
	held     int
	gapSince time.Duration

	// lastSkipAt is when this bucket last gave up on a gap and lastSkipHold
	// the hold it gave up after, so a packet arriving late can say how long
	// the gap would have needed.
	lastSkipAt   time.Duration
	lastSkipHold time.Duration

	// marks is, per path, the furthest sequence it has delivered for this
	// bucket and when. See the loss note on resequencer.
	marks [reseqMarks]pathMark
}

type heldPkt struct {
	buf []byte // nil when the slot is empty
	at  time.Duration
}

type pathMark struct {
	id   uint8
	seq  uint32
	at   time.Duration
	used bool
}

func newResequencer(write func([]byte) error, now func() time.Duration) *resequencer {
	r := &resequencer{
		write:   write,
		now:     now,
		waiting: make(map[uint16]*reseqBucket),
	}
	r.pool.New = func() any { return make([]byte, 0, bufSize) }
	r.hold.Store(int64(reseqDefaultHold))
	r.predicted.Store(int64(reseqDefaultHold))
	r.maxHold.Store(int64(reseqDefaultMaxHold))
	return r
}

// stats reads the resequencer's health for the state file.
func (r *resequencer) stats() state.Resequencer {
	r.mu.Lock()
	buffered := r.buffered
	r.mu.Unlock()
	return state.Resequencer{
		HoldMs:       float64(r.holdFor()) / float64(time.Millisecond),
		Buffered:     buffered,
		Delivered:    r.delivered.Load(),
		Reordered:    r.reordered.Load(),
		Late:         r.late.Load(),
		GapsLost:     r.lostSkipped.Load(),
		GapsTimedOut: r.timedOut.Load(),
		GapsForced:   r.forced.Load(),
		SenderResets: r.senderResets.Load(),
	}
}

// setHold sets the hold outright: both the prediction and the cap. For tests
// and for callers with nothing better to go on.
func (r *resequencer) setHold(d time.Duration) {
	r.predicted.Store(int64(d))
	r.maxHold.Store(int64(d))
	r.hold.Store(int64(d))
}

// setPredictedHold is the hold the path delays predict, and max the cap on
// any hold. The hold in force is the larger of the prediction and what gaps
// have been observed to need.
//
// The prediction alone is not enough, and the lab found out how. A path's
// round trip comes back on whichever path carries the echo, so half of it
// is not that path's one-way delay, and the difference between two paths'
// halves understates the difference between their delays - it held gaps for
// 26 ms against a real 30 ms and delivered thousands of packets late. Gap
// fill times are the thing itself, measured.
func (r *resequencer) setPredictedHold(predicted, max time.Duration) {
	r.predicted.Store(int64(predicted))
	r.maxHold.Store(int64(max))
	r.mu.Lock()
	r.recomputeHoldLocked(r.now())
	r.mu.Unlock()
}

// observeGap records how long a gap took, or would have taken, to fill.
func (r *resequencer) observeGap(d time.Duration, now time.Duration) {
	if now-r.gapWindowAt >= reseqGapWindow {
		r.gapPrev, r.gapCur, r.gapWindowAt = r.gapCur, 0, now
	}
	if d > r.gapCur {
		r.gapCur = d
	}
	r.recomputeHoldLocked(now)
}

func (r *resequencer) recomputeHoldLocked(now time.Duration) {
	if now-r.gapWindowAt >= 2*reseqGapWindow {
		r.gapPrev, r.gapCur = 0, 0
	}
	hold := time.Duration(r.predicted.Load())
	observed := r.gapCur
	if r.gapPrev > observed {
		observed = r.gapPrev
	}
	if o := time.Duration(float64(observed) * reseqGapHeadroom); o > hold {
		hold = o
	}
	if max := time.Duration(r.maxHold.Load()); hold > max {
		hold = max
	}
	r.hold.Store(int64(hold))
}

// holdFor reports the hold in force.
func (r *resequencer) holdFor() time.Duration { return time.Duration(r.hold.Load()) }

// push accepts one bulk payload that carried a flow sequence, and delivers
// it and anything it releases. The payload is copied if it has to wait.
func (r *resequencer) push(pathID uint8, bucket uint16, seq uint32, payload []byte) {
	now := r.now()
	seq &= protocol.FlowSeqMask

	r.mu.Lock()
	defer r.mu.Unlock()

	b := r.buckets[bucket%protocol.FlowBuckets]
	if b == nil {
		b = &reseqBucket{id: bucket % protocol.FlowBuckets}
		r.buckets[b.id] = b
	}
	if b.started && now-b.lastSeen > reseqIdle {
		// A flow that went quiet this long is over. Whatever arrives now is
		// a new one, or the same sender after a restart; either way the old
		// expectation means nothing.
		r.flush(b)
		b.started = false
		b.marks = [reseqMarks]pathMark{}
	}
	b.lastSeen = now
	b.mark(pathID, seq, now)
	r.pathSeen[pathID] = now
	if int(pathID) > r.maxPath {
		r.maxPath = int(pathID)
	}

	if !b.started {
		b.started, b.next, b.startAt = true, seq, now
	}

	d := protocol.FlowSeqDiff(seq, b.next)
	switch {
	case d == 0:
		if b.held > 0 {
			// A gap just filled: that is how long it needed.
			r.observeGap(now-b.gapSince, now)
		}
		r.emit(payload)
		r.advance(b, 1)
		r.drain(b, now)

	case d < -reseqRestartJump || d > reseqRestartJump:
		r.senderResets.Add(1)
		r.flush(b)
		// The marks are held against the old counters and would read every
		// new gap as already passed.
		b.marks = [reseqMarks]pathMark{}
		b.mark(pathID, seq, now)
		b.next, b.startAt = seq, now
		r.emit(payload)
		r.advance(b, 1)

	case d < 0:
		// Behind: its gap was already given up on. Deliver it rather than
		// lose it - TCP copes with a late segment far better than a missing
		// one.
		r.late.Add(1)
		if b.lastSkipAt != 0 && now-b.lastSkipAt < reseqGapWindow {
			r.observeGap(now-b.lastSkipAt+b.lastSkipHold, now)
		}
		r.emit(payload)

	default:
		if int(d) >= reseqWindow {
			// Too far ahead to hold. Give up on everything before it that
			// the window cannot reach.
			r.forced.Add(1)
			r.skip(b, int(d)-(reseqWindow-1), now)
			d = protocol.FlowSeqDiff(seq, b.next)
			if d == 0 {
				r.emit(payload)
				r.advance(b, 1)
				r.drain(b, now)
				return
			}
		}
		if b.ring == nil {
			b.ring = make([]heldPkt, reseqWindow)
		}
		slot := &b.ring[(b.head+int(d))%reseqWindow]
		if slot.buf != nil {
			return // the same packet twice; the dedup window normally catches this first
		}
		buf := r.pool.Get().([]byte)
		slot.buf = append(buf[:0], payload...)
		slot.at = now
		b.held++
		r.buffered++
		r.reordered.Add(1)
		if b.held == 1 {
			b.gapSince = now
			r.waiting[b.id] = b
		}
		for r.buffered > reseqMaxBuffered {
			if !r.forceOldest(now) {
				break
			}
		}
	}

	// Any arrival can be the one that shows every path has passed the gap
	// at the front - including an in-order packet that uncovered a new one.
	r.skipPassedGaps(b, now)
}

// mark records that a path delivered seq for this bucket.
func (b *reseqBucket) mark(pathID uint8, seq uint32, now time.Duration) {
	oldest := 0
	for i := range b.marks {
		m := &b.marks[i]
		if m.used && m.id == pathID {
			if protocol.FlowSeqDiff(seq, m.seq) > 0 || now-m.at > reseqPathActive {
				m.seq = seq
			}
			m.at = now
			return
		}
		if !m.used {
			oldest = i
			break
		}
		if m.at < b.marks[oldest].at {
			oldest = i
		}
	}
	b.marks[oldest] = pathMark{id: pathID, seq: seq, at: now, used: true}
}

// skipPassedGaps gives up on every leading gap that each active path has
// already delivered past. Paths keep their own packets in order, so such a
// gap was lost rather than delayed.
//
// A young flow needs one more condition. When a flow is first spread, the
// faster path's packets arrive before the slower path has delivered anything
// for it at all, and a check that looked only at this flow's own marks would
// see one path, find it past the gap, and give up on a packet still in
// flight. So for the first reseqPathActive of a flow, a path that is carrying
// any spread bulk counts too, and has not passed a gap until it has
// delivered past it for this flow. After that only the flow's own paths
// count - otherwise, placed per flow, every loss in a flow would wait out
// the hold for a path that will never carry it.
func (r *resequencer) skipPassedGaps(b *reseqBucket, now time.Duration) {
	young := now-b.startAt <= reseqPathActive
	for b.held > 0 {
		active, passed := false, true
		for _, m := range b.marks {
			if !m.used || now-m.at > reseqPathActive {
				continue
			}
			active = true
			if protocol.FlowSeqDiff(m.seq, b.next) <= 0 {
				passed = false
				break
			}
		}
		if passed && young {
			for id := 0; id <= r.maxPath; id++ {
				if r.pathSeen[id] == 0 || now-r.pathSeen[id] > reseqPathActive || b.hasMark(uint8(id), now) {
					continue
				}
				passed = false
				break
			}
		}
		if !active || !passed {
			return
		}
		r.lostSkipped.Add(1)
		r.skipToHeld(b, now)
	}
}

// hasMark reports whether a path has delivered for this bucket recently.
func (b *reseqBucket) hasMark(pathID uint8, now time.Duration) bool {
	for _, m := range b.marks {
		if m.used && m.id == pathID && now-m.at <= reseqPathActive {
			return true
		}
	}
	return false
}

// sweepOnce gives up on any gap that has waited out the hold.
func (r *resequencer) sweepOnce() {
	now := r.now()
	hold := r.holdFor()

	r.mu.Lock()
	defer r.mu.Unlock()
	for _, b := range r.waiting {
		for b.held > 0 && now-b.gapSince >= hold {
			r.timedOut.Add(1)
			b.lastSkipAt, b.lastSkipHold = now, hold
			r.skipToHeld(b, now)
		}
	}
}

// expire forgets buckets that have been idle past reseqIdle, returning their
// memory. Nothing is waiting in them: the hold is far shorter.
func (r *resequencer) expire() {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, b := range r.buckets {
		if b != nil && b.held == 0 && now-b.lastSeen > reseqIdle {
			r.buckets[i] = nil
		}
	}
}

// run sweeps forever.
func (r *resequencer) run() {
	var sinceExpire time.Duration
	for range time.Tick(reseqSweep) {
		r.sweepOnce()
		sinceExpire += reseqSweep
		if sinceExpire >= reseqIdle {
			sinceExpire = 0
			r.expire()
		}
	}
}

// reset abandons every expectation, delivering what is held. Called when the
// peer restarts, since its counters start again from zero.
func (r *resequencer) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, b := range r.buckets {
		if b != nil {
			r.flush(b)
			b.started = false
			b.marks = [reseqMarks]pathMark{}
		}
	}
}

// forceOldest skips the gap that has been waited on longest, to stay inside
// the memory bound. It reports whether there was one.
func (r *resequencer) forceOldest(now time.Duration) bool {
	var oldest *reseqBucket
	for _, b := range r.waiting {
		if oldest == nil || b.gapSince < oldest.gapSince {
			oldest = b
		}
	}
	if oldest == nil {
		return false
	}
	r.forced.Add(1)
	r.skipToHeld(oldest, now)
	return true
}

// skipToHeld gives up on the gap at the front of a bucket: next moves to the
// lowest held packet and everything consecutive from there is delivered.
func (r *resequencer) skipToHeld(b *reseqBucket, now time.Duration) {
	for k := 1; k < reseqWindow; k++ {
		if b.ring[(b.head+k)%reseqWindow].buf != nil {
			r.advance(b, k)
			break
		}
	}
	r.drain(b, now)
}

// skip gives up on the next n sequences, delivering any held among them in
// order.
func (r *resequencer) skip(b *reseqBucket, n int, now time.Duration) {
	for n > 0 && b.held > 0 {
		if slot := &b.ring[b.head]; slot.buf != nil {
			r.release(b, slot)
		}
		r.advance(b, 1)
		n--
	}
	if n > 0 {
		r.advance(b, n)
	}
	r.drain(b, now)
}

// drain delivers everything consecutive from next.
func (r *resequencer) drain(b *reseqBucket, now time.Duration) {
	for b.held > 0 {
		slot := &b.ring[b.head]
		if slot.buf == nil {
			break
		}
		r.release(b, slot)
		r.advance(b, 1)
	}
	if b.held == 0 {
		b.gapSince = 0
		delete(r.waiting, b.id)
		return
	}
	// A new gap is at the front. Time it from when the oldest packet now
	// waiting behind it arrived, which bounds how long any packet waits.
	for k := 1; k < reseqWindow; k++ {
		if slot := &b.ring[(b.head+k)%reseqWindow]; slot.buf != nil {
			b.gapSince = slot.at
			return
		}
	}
}

// flush delivers everything a bucket holds, in order, and empties it.
func (r *resequencer) flush(b *reseqBucket) {
	for k := 0; b.held > 0 && k < reseqWindow; k++ {
		if slot := &b.ring[(b.head+k)%reseqWindow]; slot.buf != nil {
			r.release(b, slot)
		}
	}
	b.gapSince = 0
	delete(r.waiting, b.id)
}

// release delivers one held packet and returns its buffer.
func (r *resequencer) release(b *reseqBucket, slot *heldPkt) {
	r.emit(slot.buf)
	r.pool.Put(slot.buf[:0])
	slot.buf = nil
	b.held--
	r.buffered--
}

// advance moves next forward by n.
func (r *resequencer) advance(b *reseqBucket, n int) {
	b.next = (b.next + uint32(n)) & protocol.FlowSeqMask
	if b.ring != nil {
		b.head = (b.head + n) % reseqWindow
	}
}

func (r *resequencer) emit(payload []byte) {
	r.delivered.Add(1)
	if err := r.write(payload); err != nil {
		r.writeFailures.Add(1)
	}
}
