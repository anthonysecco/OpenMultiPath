package relay

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

// Shaping to the measured link speed (D-055).
//
// Each path sends no faster than linkspeed.ShapePercent of its measured
// speed in this end's send direction, counting every byte the physical link
// carries: the inner packet, ompd's header, and the UDP/IP and WireGuard
// framing below it. A path never measured is not shaped at all.
//
// The point is where the queue forms. Sent flat out, a link queues in the
// carrier's modem, where a download sits in front of the call and nothing on
// this box can reorder it. Held just under the link's speed, the queue forms
// here instead, and here the call goes first: real-time has a band of its own
// that always drains ahead of everything else. Bulk still takes every byte the
// call does not use - ordering, not a throttle, which keeps the owner's rule
// that real-time never holds bulk back (D-052).
//
// Packets are queued unbuilt and stamped only as they leave. Two reasons,
// either sufficient: the per-path sequence must be in wire order or the far
// end counts a packet overtaken by a real-time one as lost, and the send
// timestamp must not include time spent queued here, or the far end would
// measure this box's own queue as the path degrading and move the call off a
// healthy link.
//
// Measurement traffic - probes, reports, link speed messages - is never
// queued. It is charged to the bucket like everything else but goes out at
// once, so it measures the link rather than the queue in front of it.

const (
	// shaperBurst is the bucket's depth, as time at the shaped rate: how far
	// ahead of the rate a path may send after going quiet. Deep enough that
	// the drain goroutine waking a little late costs no throughput, shallow
	// enough that the burst it releases into the modem is a few milliseconds
	// of queue, not a standing one.
	shaperBurst = 10 * time.Millisecond

	// shaperMinBurstBytes keeps a slow link's bucket able to hold two
	// full-sized packets.
	shaperMinBurstBytes = 3000

	// shaperQueueDelay bounds each band's backlog, as time at the shaped
	// rate. Past it a packet is dropped rather than queued, which is how a
	// sender's congestion control learns the link is full. About one round
	// trip on the links this project targets, which is the usual sizing for a
	// router's buffer.
	shaperQueueDelay = 100 * time.Millisecond

	// shaperMinQueueBytes is the floor for that bound, so a slow link still
	// holds enough packets for TCP to work with.
	shaperMinQueueBytes = 32 * 1500

	// shaperUnshapedQueueBytes bounds the backlog left behind when a path's
	// shaping is cleared; it drains at once.
	shaperUnshapedQueueBytes = 4 << 20

	// shaperRoom is the bulk backlog, as time at the shaped rate, below which
	// the cascade will still place bulk on a path. Past it the cascade spills
	// onto the next path in the fill order. The same ten milliseconds the
	// cascade's own allowance bucket used to hold, for the same reason: a
	// deeper backlog absorbs a sender's probe above its rate instead of
	// letting it spill and find the next link.
	shaperRoom = 10 * time.Millisecond
)

// Bands, drained strictly in order.
const (
	bandRealtime = 0
	bandOther    = 1
	shaperBands  = 2
)

// shapedPacket is one queued, unbuilt data packet.
type shapedPacket struct {
	class     uint8
	globalSeq uint32
	tag       flowTag
	payload   []byte
	buf       *[]byte // the pooled backing array payload lives in
}

var payloadPool = sync.Pool{New: func() any {
	b := make([]byte, bufSize)
	return &b
}}

// pathShaper shapes one path's sends.
type pathShaper struct {
	now   func() time.Duration
	build func(p *shapedPacket, buf []byte) []byte
	write func(pkt []byte)
	cost  func(n int) int

	// sendMu serialises building and writing, so the per-path sequence
	// assigned at build is the order packets reach the wire in.
	sendMu  sync.Mutex
	scratch []byte

	mu       sync.Mutex
	rateBps  float64 // bytes a second at the IP layer; 0 is unshaped
	tokens   float64
	at       time.Duration
	bands    [shaperBands][]*shapedPacket
	queued   [shaperBands]int // payload bytes waiting in each band
	inflight int              // packets popped by the drain goroutine but not yet written
	running  bool
	wake     chan struct{} // something was queued
	reshaped chan struct{} // the rate changed; a wait worked out at the old one is void

	dropped atomic.Uint64
}

func newPathShaper(now func() time.Duration, build func(*shapedPacket, []byte) []byte, write func([]byte), cost func(int) int) *pathShaper {
	return &pathShaper{
		now:      now,
		build:    build,
		write:    write,
		cost:     cost,
		scratch:  make([]byte, 0, bufSize+maxHeaderLen),
		wake:     make(chan struct{}, 1),
		reshaped: make(chan struct{}, 1),
	}
}

// setRate shapes the path to kbps, or unshapes it for 0.
func (s *pathShaper) setRate(kbps float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rate := kbps * 1000 / 8
	if rate < 0 {
		rate = 0
	}
	if rate == s.rateBps {
		return
	}
	if s.rateBps == 0 {
		// Start from an empty bucket rather than a full one: a path that was
		// just flooding unshaped has already spent what a full bucket would
		// release again.
		s.tokens, s.at = 0, s.now()
	}
	s.rateBps = rate
	if rate > 0 && !s.running {
		s.running = true
		go s.drain()
	}
	select {
	case s.reshaped <- struct{}{}:
	default:
	}
}

// kbps is the rate the path is shaped to, or 0 when it is not.
func (s *pathShaper) kbps() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rateBps * 8 / 1000
}

// backlog is the payload bytes waiting in both bands.
func (s *pathShaper) backlog() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queued[bandRealtime] + s.queued[bandOther]
}

// hasRoom reports whether the cascade may place more bulk here: always on an
// unshaped path, and on a shaped one while its backlog is under shaperRoom.
func (s *pathShaper) hasRoom() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rateBps == 0 {
		return true
	}
	return float64(s.queued[bandOther]) < s.bytesFor(shaperRoom, shaperMinBurstBytes)
}

// send transmits one data packet, now if the bucket allows and nothing is
// waiting ahead of it, otherwise queued in its class's band.
func (s *pathShaper) send(class uint8, globalSeq uint32, tag flowTag, payload []byte) {
	s.mu.Lock()
	if s.idleLocked() {
		ok := true
		if s.rateBps > 0 {
			s.refillLocked()
			ok = s.tokens >= 0
		}
		if ok {
			s.inflight++
			s.mu.Unlock()
			p := shapedPacket{class: class, globalSeq: globalSeq, tag: tag, payload: payload}
			n := s.transmit(&p)
			s.mu.Lock()
			s.inflight--
			if s.rateBps > 0 {
				s.tokens -= float64(n)
			}
			s.mu.Unlock()
			return
		}
	}

	band := bandOther
	if class == protocol.ClassRealtime {
		band = bandRealtime
	}
	if float64(s.queued[band]+len(payload)) > s.limitLocked() {
		s.mu.Unlock()
		s.dropped.Add(1)
		return
	}
	buf := payloadPool.Get().(*[]byte)
	if cap(*buf) < len(payload) {
		*buf = make([]byte, len(payload))
	}
	p := &shapedPacket{
		class: class, globalSeq: globalSeq, tag: tag,
		payload: append((*buf)[:0], payload...), buf: buf,
	}
	s.bands[band] = append(s.bands[band], p)
	s.queued[band] += len(payload)
	s.signal()
	s.mu.Unlock()
}

// charge accounts for a packet sent outside the queue - measurement traffic,
// which goes out at once - so the data behind it waits its share.
func (s *pathShaper) charge(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rateBps == 0 {
		return
	}
	s.refillLocked()
	s.tokens -= float64(s.cost(n))
}

// transmit builds and writes one packet, returning what it cost on the wire.
func (s *pathShaper) transmit(p *shapedPacket) int {
	s.sendMu.Lock()
	out := s.build(p, s.scratch)
	s.write(out)
	n := s.cost(len(out))
	s.sendMu.Unlock()
	return n
}

// drain sends queued packets as the bucket allows. One per shaped path, for
// the life of the process; a path whose shaping is cleared simply empties its
// queue at once and waits.
func (s *pathShaper) drain() {
	for {
		s.mu.Lock()
		for s.bands[bandRealtime] == nil && s.bands[bandOther] == nil {
			s.mu.Unlock()
			<-s.wake
			s.mu.Lock()
		}
		if s.rateBps > 0 {
			s.refillLocked()
			if s.tokens < 0 {
				wait := time.NewTimer(time.Duration(-s.tokens / s.rateBps * float64(time.Second)))
				s.mu.Unlock()
				// A rate cleared or raised mid-wait takes effect now, not when
				// a wait worked out at the old rate runs out - on a slow link
				// that was most of a second.
				select {
				case <-wait.C:
				case <-s.reshaped:
					wait.Stop()
				}
				continue
			}
		}
		band := bandRealtime
		if s.bands[band] == nil {
			band = bandOther
		}
		p := s.bands[band][0]
		s.bands[band][0] = nil
		if s.bands[band] = s.bands[band][1:]; len(s.bands[band]) == 0 {
			s.bands[band] = nil
		}
		s.queued[band] -= len(p.payload)
		s.inflight++
		s.mu.Unlock()

		n := s.transmit(p)
		payloadPool.Put(p.buf)

		s.mu.Lock()
		s.inflight--
		if s.rateBps > 0 {
			s.tokens -= float64(n)
		}
		s.mu.Unlock()
	}
}

// idleLocked reports whether nothing is queued or on its way out, so a new
// packet sent directly cannot overtake one sent before it.
func (s *pathShaper) idleLocked() bool {
	return s.inflight == 0 && s.bands[bandRealtime] == nil && s.bands[bandOther] == nil
}

func (s *pathShaper) refillLocked() {
	now := s.now()
	if elapsed := now - s.at; elapsed > 0 {
		s.tokens += s.rateBps * elapsed.Seconds()
	}
	s.at = now
	if depth := s.bytesFor(shaperBurst, shaperMinBurstBytes); s.tokens > depth {
		s.tokens = depth
	}
}

// limitLocked is the most a band may hold.
func (s *pathShaper) limitLocked() float64 {
	if s.rateBps == 0 {
		return shaperUnshapedQueueBytes
	}
	return s.bytesFor(shaperQueueDelay, shaperMinQueueBytes)
}

// bytesFor is d's worth of the shaped rate, and at least floor.
func (s *pathShaper) bytesFor(d time.Duration, floor float64) float64 {
	if b := s.rateBps * d.Seconds(); b > floor {
		return b
	}
	return floor
}

func (s *pathShaper) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
