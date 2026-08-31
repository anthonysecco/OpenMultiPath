package relay

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

// echoInterval is how often measurement feedback is attached to outgoing
// packets. protocol.md puts ~10 reports/sec at a few kbps: cheap enough to
// be worth it, frequent enough for the 100-200 ms reaction target.
const echoInterval = 100 * time.Millisecond

// staleEcho is the age past which a recorded arrival is dropped rather than
// echoed. A reading this old tells the peer nothing useful about current
// conditions, and echoing it would also risk overflowing the microsecond
// hold time carried on the wire.
const staleEcho = 10 * time.Second

// statsInterval is how often per-path measurements are logged. This is
// scaffolding to make the echo channel observable until the real telemetry
// and web UI land.
const statsInterval = 30 * time.Second

// pathState is the per-path bookkeeping both ends keep.
type pathState struct {
	// nextSeq is the per-path sequence stamped on the next transmit.
	nextSeq uint32

	// wantSeq is the per-path sequence expected next from the peer, and
	// started guards it until the first packet establishes a baseline.
	wantSeq uint32
	started bool

	// The last packet seen from the peer on this path, held so its
	// timestamp can be echoed back with our own hold time subtracted out.
	peerTS  uint32
	seenAt  time.Duration
	pending bool

	// remote is where this path's traffic goes. Only the responder uses
	// it: it learns each path's address as packets arrive, since the RV
	// dials out from behind CGNAT and its addresses move. The initiator
	// pins its paths to sockets instead, one per WAN link.
	remote *net.UDPAddr

	// Measurements. These are deliberately just counters and a last
	// reading; percentiles, burst distribution and the rest of the
	// statistics belong to the measurement step.
	lost     uint64
	received uint64
	rtt      uint32 // most recent round trip, microseconds
}

// session holds the sequencing and measurement state that both ends of the
// tunnel keep. Timestamps are microseconds since this process started, so
// the two ends share no epoch and need no clock synchronisation - a
// sender's readings are only ever compared against its own.
type session struct {
	start     time.Time
	globalSeq atomic.Uint32

	mu       sync.Mutex
	paths    map[uint8]*pathState
	lastEcho time.Duration
}

func newSession() *session {
	return &session{
		start: time.Now(),
		paths: make(map[uint8]*pathState),
	}
}

// elapsed is the single clock reading everything else derives from.
func (s *session) elapsed() time.Duration { return time.Since(s.start) }

// nextGlobalSeq allocates the sequence for one packet. It is called once
// per packet before path selection, so every copy of a duplicated packet
// carries the same global sequence and can be recognised as the same
// packet at the far end.
func (s *session) nextGlobalSeq() uint32 { return s.globalSeq.Add(1) }

// pathLocked returns the state for a path, creating it on first use. The
// path id is a byte, so a peer sending nonsense ids can create at most 256
// entries.
func (s *session) pathLocked(id uint8) *pathState {
	p := s.paths[id]
	if p == nil {
		p = &pathState{}
		s.paths[id] = p
	}
	return p
}

// pathRemote pairs a path with where its traffic currently goes.
type pathRemote struct {
	pathID uint8
	addr   *net.UDPAddr
}

// setRemote records where a path's traffic should be sent, learned from
// the packets arriving on it.
func (s *session) setRemote(id uint8, addr *net.UDPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pathLocked(id).remote = addr
}

// remotes returns every path whose address is known.
func (s *session) remotes() []pathRemote {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]pathRemote, 0, len(s.paths))
	for id, p := range s.paths {
		if p.remote != nil {
			out = append(out, pathRemote{pathID: id, addr: p.remote})
		}
	}
	return out
}

// stamp builds the wire header for one copy of a packet and returns the
// header followed by the payload, appended into buf.
//
// globalSeq is passed in rather than allocated here because it must be
// assigned once per packet before path selection, while the per-path
// sequence is assigned here, at transmit on this specific path.
func (s *session) stamp(pathID uint8, globalSeq uint32, payload, buf []byte) []byte {
	now := s.elapsed()

	s.mu.Lock()
	p := s.pathLocked(pathID)
	h := protocol.Header{
		Type: protocol.TypeData,
		// Classification is a later step; until then nothing is
		// distinguished as real-time.
		Class:     protocol.ClassUnknown,
		PathID:    pathID,
		GlobalSeq: globalSeq,
		PathSeq:   p.nextSeq,
		SendTS:    uint32(now.Microseconds()),
	}
	p.nextSeq++

	if now-s.lastEcho >= echoInterval {
		h.Echo = s.collectEchoLocked(now)
		if len(h.Echo) > 0 {
			s.lastEcho = now
		}
	}
	s.mu.Unlock()

	return append(h.AppendTo(buf[:0]), payload...)
}

// collectEchoLocked drains the pending arrivals into echo entries, one per
// path with something to report. Reporting every path in a single packet
// gives the peer one consistent snapshot rather than readings taken at
// slightly different moments.
func (s *session) collectEchoLocked(now time.Duration) []protocol.EchoEntry {
	var out []protocol.EchoEntry
	for id, p := range s.paths {
		if !p.pending {
			continue
		}
		p.pending = false
		held := now - p.seenAt
		if held > staleEcho {
			continue
		}
		out = append(out, protocol.EchoEntry{
			PathID: id,
			TS:     p.peerTS,
			Delay:  uint32(held.Microseconds()),
		})
	}
	return out
}

// observe records what an incoming packet tells us: that this path is
// alive and when it arrived, whether anything was lost on it, and what the
// peer's echo says about our own round trip.
func (s *session) observe(h *protocol.Header) {
	now := s.elapsed()
	nowTS := uint32(now.Microseconds())

	s.mu.Lock()
	defer s.mu.Unlock()

	p := s.pathLocked(h.PathID)
	p.received++
	p.peerTS = h.SendTS
	p.seenAt = now
	p.pending = true

	// Per-path sequences are strictly monotonic, so a jump past what was
	// expected is real loss on this path. A global sequence gap would mean
	// almost nothing here, since reordering between paths is normal.
	//
	// A gap is counted the moment it appears and is not retracted if the
	// straggler turns up later, which slightly over-counts loss when a
	// single path reorders internally. That follows protocol.md's premise
	// that within one path a gap is unambiguous; revisit it with a reorder
	// window if the field data says otherwise.
	switch {
	case !p.started:
		p.started = true
		p.wantSeq = h.PathSeq + 1
	case protocol.SeqAfter(h.PathSeq, p.wantSeq):
		p.lost += uint64(h.PathSeq - p.wantSeq)
		p.wantSeq = h.PathSeq + 1
	case h.PathSeq == p.wantSeq:
		p.wantSeq = h.PathSeq + 1
	}

	// The echo carries back timestamps we ourselves sent, along with how
	// long the peer sat on them. Subtracting that hold time leaves the
	// round trip, with no dependence on the two clocks agreeing.
	for _, e := range h.Echo {
		round := protocol.MicrosSince(nowTS, e.TS)
		if round < e.Delay {
			continue // hold time exceeds the round trip; not a reading of ours
		}
		s.pathLocked(e.PathID).rtt = round - e.Delay
	}
}

// logStats periodically reports what the echo channel is measuring. This is
// scaffolding for the measurement and telemetry steps that follow.
func (s *session) logStats() {
	for range time.Tick(statsInterval) {
		s.mu.Lock()
		for id, p := range s.paths {
			log.Printf("path %d: rtt %.1f ms, %d received, %d lost",
				id, float64(p.rtt)/1000, p.received, p.lost)
		}
		s.mu.Unlock()
	}
}
