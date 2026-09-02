package relay

import (
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
	"github.com/anthonysecco/OpenMultiPath/internal/record"
	"github.com/anthonysecco/OpenMultiPath/internal/state"
)

// The two ends run the same session code and differ only in role. The
// initiator owns the physical sockets and so has paths that can be bound
// or not; the responder learns its paths from whatever arrives.
const (
	roleInitiator = "initiator"
	roleResponder = "responder"
)

// staleEcho is the age past which a recorded arrival is dropped rather
// than echoed. A reading this old says nothing about current conditions,
// and echoing it would risk overflowing the microsecond hold time on the
// wire.
const staleEcho = 10 * time.Second

// Overheads below the tunnel, used to turn a discovered path MTU into a
// usable inner MTU.
const (
	ipUDPOverhead     = 28
	wireGuardOverhead = 32

	// minTunnelMTU is the IPv6 minimum link MTU. architecture.md is
	// explicit that a path unable to carry this is broken and should be
	// flagged rather than accommodated.
	minTunnelMTU = 1280

	// minUsablePathMTU is the smallest physical MTU that can still carry
	// the tunnel floor once every layer below it has taken its cut. A path
	// under this cannot carry a conforming tunnel at all, however healthy
	// it looks otherwise, and is excluded rather than accommodated.
	minUsablePathMTU = minTunnelMTU + ipUDPOverhead + protocol.MaxDataHeaderLen + wireGuardOverhead
)

// mtuLadder is the set of physical MTUs probed for, smallest first. A
// short ladder rather than a binary search: it keeps the failure behaviour
// obvious, and the rungs are close enough together in the interesting
// range not to give away much to coarseness. Nothing below
// minUsablePathMTU is worth probing, since a path that fails the first
// rung cannot carry the tunnel regardless of how much less it can carry.
var mtuLadder = [...]int{minUsablePathMTU, 1420, 1440, 1460, 1480, 1500}

// probeTimeout is how long a probe waits for confirmation before counting
// as a miss.
const probeTimeout = 2 * time.Second

// probeMisses is how many unconfirmed attempts retire a candidate size.
const probeMisses = 3

// mtuCeilingRetryAfter is how long a ceiling holds before the search tries
// again from scratch.
//
// Three misses at the default cadence is ~45s, which a real dead zone
// clears easily - the scenario walkthrough in scope-v1.md has these running
// to minutes. Without a retry, a ceiling set during an ordinary outage
// would never be reconsidered: confirmed stays 0 forever, the path reads as
// unable to carry the tunnel floor, and only a daemon restart clears it.
// That is exactly backwards for a project whose premise is that links come
// back.
const mtuCeilingRetryAfter = 3 * time.Minute

// mtuProbe tracks the path MTU search for one path. Sizes are physical
// MTUs: what the link carries including the outer IP and UDP headers.
type mtuProbe struct {
	confirmed int // largest size confirmed to arrive
	probing   int // size currently outstanding, 0 when idle
	sentAt    time.Duration
	misses    int
	ceiling   int           // sizes at or above this have failed; stop reaching
	ceilingAt time.Duration // when ceiling was set, so it can be retried later
}

// next returns the size to probe for, or 0 when the search has settled.
func (m *mtuProbe) next() int {
	for _, size := range mtuLadder {
		if size <= m.confirmed {
			continue
		}
		if m.ceiling != 0 && size >= m.ceiling {
			return 0
		}
		return size
	}
	return 0
}

type pathState struct {
	// nextSeq is the per-path sequence stamped on the next transmit.
	nextSeq uint32

	// wantSeq is the per-path sequence expected next from the peer, and
	// started guards it until the first packet sets a baseline.
	wantSeq uint32
	started bool

	// The last packet seen from the peer on this path, held so its
	// timestamp can be echoed back with our own hold time subtracted out.
	peerTS  uint32
	seenAt  time.Duration
	pending bool

	// maxSeen is the largest packet received on this path since the last
	// report, which is what confirms the peer's MTU probes.
	maxSeen uint16

	// remote is where this path's traffic goes. Only the responder uses
	// it: it learns each path's address as packets arrive, since the RV
	// dials out from behind CGNAT and its addresses move. The initiator
	// pins its paths to sockets instead, one per WAN link.
	remote *net.UDPAddr

	// bound, local and drops describe the physical socket behind this
	// path. Only the initiator owns sockets; the responder learns its
	// paths from arriving packets and leaves these alone.
	//
	// bound is deliberately separate from whether the path is delivering.
	// A path that is bound but silent says the link is up locally and
	// something beyond it is broken, which is a different fault from a
	// modem that has not registered, and wants telling apart at 2am.
	bound bool
	local string
	drops uint64

	// lastSentAt is when anything last went out on this path, which is
	// what paces the standalone reports. It is per-path and not
	// session-wide for a reason that only appeared once scheduling did:
	// with one path carrying the traffic, a session-wide timer is kept
	// permanently fresh by the chosen path and the idle ones are never
	// reported on at all. They then stop being measured, which loses
	// exactly the paths worth knowing about - the ones a call might have
	// to be moved onto.
	//
	// It also gives protocol.md's stated rule for free: probe rate
	// inversely proportional to traffic on that path. A busy path is never
	// due, an idle one gets the full cadence.
	lastSentAt time.Duration

	// sentSince counts packets put into this path since anything last
	// arrived on it. Silence on its own is the ordinary state of an idle
	// path; silence while we are actively sending is a path that has
	// stopped working, and telling those apart is what stops an unused
	// link being declared dead for failing to answer a question nobody
	// asked it.
	sentSince uint64

	// confirmedAt is when the peer last echoed a packet we sent on this
	// path, which is the only direct evidence that our transmissions
	// arrive. Receiving on a path proves the reverse direction only.
	// Make-before-break turns on this distinction: committing a handover
	// on inbound evidence alone would move a call onto a path that is fine
	// coming back and dead going out.
	confirmedAt time.Duration

	rtt   uint32 // most recent round trip, microseconds
	stats pathStats
	mtu   mtuProbe
	bw    bwEstimate

	// rttFloor is the smallest round trip seen on this path, re-armed on a
	// long window. It is the part of the delay that belongs to the path
	// itself rather than to anything queued on it, and it is what the
	// outbound delay estimate is anchored to - the instantaneous round trip
	// includes queueing in *both* directions, which is precisely the
	// contamination step 6c exists to remove.
	rttFloor rttFloor

	// peer is what the far end last told us about our own transmissions on
	// this path. Zero value means it has never said, which is not the same
	// as it having said the path is bad.
	peer peerView
}

// peerView is the far end's measurement of our send direction on one path.
//
// Everything here is a difference against that path's own floor at the
// receiving end, so none of it depends on the two clocks agreeing. There is
// no absolute one-way delay because none can be measured without
// synchronised clocks; see outboundDelayMs for how the absolute part is
// approximated and why that is defensible.
type peerView struct {
	spreadMs float64
	queueMs  float64
	jitterMs float64
	loss     float64
	burst    float64

	at    time.Duration
	valid bool
}

// peerViewStale is how long a report is believed. Reports arrive about once
// a second, so this tolerates a handful going missing before the scheduler
// stops trusting the picture and falls back to round-trip scoring.
const peerViewStale = 10 * time.Second

func (v peerView) fresh(now time.Duration) bool {
	return v.valid && now-v.at < peerViewStale
}

// rttFloor tracks the smallest round trip on a path, re-armed on a two
// window scheme so a path whose base delay genuinely moves is not measured
// forever against a floor that no longer exists.
type rttFloor struct {
	cur, next uint32
	have      bool
	started   time.Duration
}

// rttFloorWindow matches the bandwidth estimator's: long enough that a
// standing queue is not absorbed into the baseline, which is the whole
// reason the floor is being kept.
const rttFloorWindow = 5 * time.Minute

func (f *rttFloor) observe(now time.Duration, rtt uint32) {
	if rtt == 0 {
		return
	}
	if !f.have {
		f.have, f.cur, f.next, f.started = true, rtt, rtt, now
		return
	}
	if rtt < f.cur {
		f.cur = rtt
	}
	if rtt < f.next {
		f.next = rtt
	}
	if now-f.started >= rttFloorWindow {
		f.cur, f.next, f.started = f.next, rtt, now
	}
}

// session holds the sequencing and measurement state both ends keep.
// Timestamps are microseconds since this process started, so the two ends
// share no epoch and need no clock synchronisation: a sender's readings
// are only ever compared against its own.
type session struct {
	start     time.Time
	globalSeq atomic.Uint32

	// cfg carries the settings that can change while running, so a
	// cadence altered through the web interface takes effect without a
	// restart.
	cfg *config.Holder

	node string
	role string

	// sched publishes the current scheduling verdict. It is set once
	// before the relay starts and only ever read here, for the snapshot.
	// The snapshot copes with it being nil, because the measurement layer
	// is tested on its own without a scheduler attached.
	sched *scheduler

	// authKey authenticates the wire header when set. It is loaded from a
	// file rather than the hot-reload configuration on purpose: the web
	// interface serves that configuration over HTTP, and a shared secret
	// has no business in a response any browser on the LAN can fetch.
	authKey []byte

	// peerVersion is the highest wire version the far end has been heard
	// speaking. It only ever rises: once a peer has demonstrated it can
	// read version 2, a forged or corrupt version 1 packet must not be able
	// to talk us back down into sending unauthenticated headers.
	peerVersion atomic.Uint32

	mu         sync.Mutex
	paths      map[uint8]*pathState
	names      map[uint8]string
	lastEcho   time.Duration
	lastReport time.Duration
}

func newSession(cfg *config.Holder, node, role string) *session {
	if cfg == nil {
		cfg = config.NewHolder(config.Defaults())
	}
	s := &session{
		start: time.Now(),
		cfg:   cfg,
		node:  node,
		role:  role,
		paths: make(map[uint8]*pathState),
		names: make(map[uint8]string),
	}
	s.peerVersion.Store(protocol.MinVersion)
	return s
}

// setAuthKey installs the shared secret that authenticates the header.
func (s *session) setAuthKey(key []byte) { s.authKey = key }

// emitVersion is the wire version to speak: the newest both ends can read.
func (s *session) emitVersion() uint8 { return uint8(s.peerVersion.Load()) }

// notePeerVersion records that the peer spoke this version, never
// downwards. See the field comment for why the ratchet matters.
func (s *session) notePeerVersion(v uint8) {
	for {
		cur := s.peerVersion.Load()
		if uint32(v) <= cur {
			return
		}
		if s.peerVersion.CompareAndSwap(cur, uint32(v)) {
			log.Printf("peer speaks wire version %d", v)
			return
		}
	}
}

// nameFor labels a path with the interface it leaves by, where that is
// known. The responder only ever learns path numbers.
func (s *session) nameFor(id uint8, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.names[id] = name
}

// elapsed is the single clock reading everything else derives from.
func (s *session) elapsed() time.Duration { return time.Since(s.start) }

// nextGlobalSeq allocates the sequence for one packet. It is called once
// per packet before path selection, so every copy of a duplicated packet
// carries the same global sequence and is recognisable as the same packet
// at the far end.
func (s *session) nextGlobalSeq() uint32 { return s.globalSeq.Add(1) }

// registerPath declares a path that exists whether or not anything has
// arrived on it, so reports and probes can be sent down a path that has
// never been heard from - which is exactly the path worth probing.
func (s *session) registerPath(id uint8) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pathLocked(id)
}

// setBound records that a path's socket is open on a local address.
func (s *session) setBound(id uint8, local string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.pathLocked(id)
	p.bound, p.local = true, local
}

// setUnbound records that a path's socket has gone away, and counts it.
//
// The count is kept because the flap penalty in protocol.md will need it,
// and because a link that has gone down forty times on one drive is the
// single most useful thing the field data can tell us about it.
func (s *session) setUnbound(id uint8) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.pathLocked(id)
	if p.bound {
		p.drops++
	}
	p.bound, p.local = false, ""
}

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

// remoteFor returns where a single path's traffic goes, or nil if that
// path has not been heard from.
func (s *session) remoteFor(id uint8) *net.UDPAddr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.paths[id]; p != nil {
		return p.remote
	}
	return nil
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

// stamp builds one copy of a data packet: the wire header followed by the
// payload, appended into buf.
//
// globalSeq is passed in rather than allocated here because it must be
// assigned once per packet before path selection, while the per-path
// sequence is assigned here, at transmit on this specific path.
func (s *session) stamp(pathID uint8, globalSeq uint32, payload, buf []byte) []byte {
	return s.build(protocol.TypeData, pathID, globalSeq, payload, buf)
}

func (s *session) build(typ, pathID uint8, globalSeq uint32, payload, buf []byte) []byte {
	return s.buildWith(typ, pathID, globalSeq, payload, buf, nil)
}

func (s *session) buildWith(typ, pathID uint8, globalSeq uint32, payload, buf []byte, reports []protocol.ReportEntry) []byte {
	now := s.elapsed()

	s.mu.Lock()
	p := s.pathLocked(pathID)
	h := protocol.Header{
		Type: typ,
		// Classification is a later step; until then nothing is
		// distinguished as real-time.
		Class:     protocol.ClassUnknown,
		PathID:    pathID,
		GlobalSeq: globalSeq,
		PathSeq:   p.nextSeq,
		SendTS:    uint32(now.Microseconds()),
		Reports:   reports,
	}
	p.nextSeq++
	p.sentSince++

	if now-s.lastEcho >= s.cfg.Get().EchoInterval() {
		h.Echo = s.collectEchoLocked(now)
		if len(h.Echo) > 0 {
			s.lastEcho = now
		}
	}
	p.lastSentAt = now

	// Built under the lock so the bandwidth estimate can count what actually
	// went onto the wire rather than an estimate of it. The header's length
	// varies with how many echo entries rode along, and a rate derived from
	// a guess at that would be wrong in exactly the direction that matters:
	// echoes are largest when the most paths need reporting on.
	out := append(h.AppendTo(buf[:0], s.emitVersion(), s.authKey), payload...)
	p.bw.noteSent(len(out) + ipUDPOverhead)
	s.mu.Unlock()

	return out
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
		if len(out) == protocol.MaxEchoEntries {
			break // the rest ride the next report
		}
		p.pending = false
		held := now - p.seenAt
		if held > staleEcho {
			continue
		}
		out = append(out, protocol.EchoEntry{
			PathID:  id,
			TS:      p.peerTS,
			Delay:   uint32(held.Microseconds()),
			MaxSeen: p.maxSeen,
		})
		p.maxSeen = 0
	}
	return out
}

// dueForReport reports whether a path has been quiet long enough that
// feedback needs a packet of its own. Piggybacking on data is free, so it
// is always preferred; this only fires for a path with no data to ride
// along with.
func (s *session) dueForReport(id uint8) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.elapsed()-s.pathLocked(id).lastSentAt >= s.cfg.Get().EchoInterval()
}

// buildReport produces a standalone feedback packet for a path, carrying no
// payload of its own.
//
// This is where path reports ride. They go only on these packets and never
// on data, so a data packet's header stays small enough that the tunnel MTU
// does not have to budget for a block sent once a second.
func (s *session) buildReport(pathID uint8, buf []byte) []byte {
	now := s.elapsed()

	var reports []protocol.ReportEntry
	if s.emitVersion() >= 2 {
		s.mu.Lock()
		if now-s.lastReport >= s.cfg.Get().ReportInterval() {
			reports = s.collectReportsLocked()
			if len(reports) > 0 {
				s.lastReport = now
			}
		}
		s.mu.Unlock()
	}

	return s.buildWith(protocol.TypeReport, pathID, s.nextGlobalSeq(), nil, buf, reports)
}

// collectReportsLocked describes what we have measured on the peer's
// transmissions, one entry per path we have heard anything on.
//
// It reports on paths rather than on recent arrivals, unlike the echo
// block: a path that has gone quiet is exactly the one the peer most needs
// told about, because silence at this end is how its send direction failing
// looks from here.
func (s *session) collectReportsLocked() []protocol.ReportEntry {
	out := make([]protocol.ReportEntry, 0, len(s.paths))
	for id, p := range s.paths {
		if p.stats.received == 0 {
			continue // nothing measured, so nothing honest to say
		}
		if len(out) == protocol.MaxReportEntries {
			break // the rest ride the next report
		}
		st := &p.stats
		out = append(out, protocol.ReportEntry{
			PathID:        id,
			SpreadTenthMs: tenthMs(msi(st.spread())),
			QueueTenthMs:  tenthMs(msi(st.queueDelay)),
			JitterTenthMs: tenthMs(st.jitter / 1000),
			LossPerMille:  perMille(st.recentLossPercent()),
			BurstTenths:   tenths(st.recentBurstRatio()),
		})
	}
	return out
}

// tenthMs converts milliseconds to the wire's tenths, saturating rather
// than wrapping. Saturation is the right failure: the values that overflow
// are ones where the path is already far past any threshold that matters,
// and a wrapped small number would read as healthy.
func tenthMs(ms float64) uint16 {
	v := ms * 10
	if v < 0 {
		return 0
	}
	if v > math.MaxUint16 {
		return math.MaxUint16
	}
	return uint16(v)
}

func perMille(percent float64) uint16 {
	v := percent * 10
	if v < 0 {
		return 0
	}
	if v > 1000 {
		return 1000
	}
	return uint16(v)
}

func tenths(ratio float64) uint8 {
	v := ratio * 10
	if v < 0 {
		return 0
	}
	if v > math.MaxUint8 {
		return math.MaxUint8
	}
	return uint8(v)
}

// buildProbe produces an MTU probe for a path, padded so the whole packet
// is exactly size bytes on the wire, or nil when the search has settled.
//
// The padding is what is being measured, so probes are deliberately the
// same shape as data: protocol.md warns that a small probe experiences
// different serialisation delay than a full-sized packet, enough to bias
// comparisons between paths.
func (s *session) buildProbe(pathID uint8, buf []byte) []byte {
	now := s.elapsed()

	s.mu.Lock()
	p := s.pathLocked(pathID)
	if p.mtu.probing != 0 && now-p.mtu.sentAt < probeTimeout {
		s.mu.Unlock()
		return nil // one still outstanding
	}
	if p.mtu.probing != 0 {
		// The outstanding probe timed out unconfirmed.
		p.mtu.misses++
		if p.mtu.misses >= probeMisses {
			p.mtu.ceiling = p.mtu.probing
			p.mtu.ceilingAt = now
			p.mtu.misses = 0
		}
		p.mtu.probing = 0
	}
	if p.mtu.ceiling != 0 && now-p.mtu.ceilingAt >= mtuCeilingRetryAfter {
		// Give the search another chance rather than trusting a ceiling
		// that may only ever have meant "the path was down at the time."
		p.mtu.ceiling = 0
	}
	size := p.mtu.next()
	if size == 0 {
		s.mu.Unlock()
		return nil
	}
	p.mtu.probing = size
	p.mtu.sentAt = now
	s.mu.Unlock()

	// The probe has to arrive as one datagram of the size being tested, so
	// pad the payload out to whatever the header did not fill.
	wire := size - ipUDPOverhead
	out := s.build(protocol.TypeProbe, pathID, s.nextGlobalSeq(), nil, buf)
	if pad := wire - len(out); pad > 0 {
		out = append(out, zeroPad[:pad]...)
		// The padding is real traffic on the link and is counted as such.
		// A 1500 byte probe every fifteen seconds is nothing next to a
		// download, but on an otherwise idle path it is most of what is
		// there, and leaving it out would understate the only load the
		// path has.
		s.mu.Lock()
		p.bw.noteSent(pad)
		s.mu.Unlock()
	}
	return out
}

// zeroPad is the filler MTU probes are padded with.
var zeroPad = make([]byte, mtuLadder[len(mtuLadder)-1])

// runProbes keeps measurement flowing when the tunnel is quiet.
//
// Passive measurement is structurally blind on an idle path, and an idle
// path is exactly the one that has to be understood before traffic is ever
// steered onto it. Reports go out only when there is no data to ride
// along with, so a busy tunnel pays nothing for this.
//
// send is what actually puts a packet on a path; pathIDs names the paths
// currently worth sending on, which for the responder only becomes known
// as the far end makes contact.
func (s *session) runProbes(pathIDs func() []uint8, send func(pathID uint8, pkt []byte)) {
	// A fixed fast tick with the intervals checked against the clock,
	// rather than tickers built from them. The cadences are adjustable
	// while running, and this way a change takes effect on the next tick
	// instead of needing the tickers torn down and rebuilt.
	const tick = 20 * time.Millisecond
	var lastProbe time.Duration

	buf := make([]byte, 0, bufSize+maxHeaderLen)
	for range time.Tick(tick) {
		now := s.elapsed()

		for _, id := range pathIDs() {
			if s.dueForReport(id) {
				send(id, s.buildReport(id, buf))
			}
		}

		if now-lastProbe >= s.cfg.Get().ProbeInterval() {
			lastProbe = now
			for _, id := range pathIDs() {
				if pkt := s.buildProbe(id, buf); pkt != nil {
					send(id, pkt)
				}
			}
		}
	}
}

// observe records what an incoming packet tells us: that this path is
// alive and when it arrived, whether anything was lost on it, how big a
// packet it managed to carry, and what the peer's echo says about our own
// round trip.
func (s *session) observe(h *protocol.Header, wireLen int) {
	now := s.elapsed()
	nowTS := uint32(now.Microseconds())

	s.mu.Lock()
	defer s.mu.Unlock()

	p := s.pathLocked(h.PathID)
	p.peerTS = h.SendTS
	p.seenAt = now
	p.pending = true
	p.sentSince = 0
	if uint16(wireLen) > p.maxSeen {
		p.maxSeen = uint16(wireLen)
	}

	// Transit is the arrival on our clock minus the send on theirs. The
	// two share no epoch, so the value is meaningless on its own, but
	// jitter and queue delay are both differences in which the constant
	// offset cancels.
	if p.stats.observeTransit(protocol.MicrosSince(nowTS, h.SendTS), now) {
		// The peer restarted. Its per-path sequence went back to zero
		// with everything else, and the counter we were expecting is now
		// far ahead of anything it will send. Left alone, every packet
		// from here on would read as ancient and sequence tracking would
		// never recover.
		p.started = false
	}

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
		p.stats.observeDelivered()
	case protocol.SeqAfter(h.PathSeq, p.wantSeq):
		p.stats.observeLoss(h.PathSeq - p.wantSeq)
		p.wantSeq = h.PathSeq + 1
		p.stats.observeDelivered()
	case h.PathSeq == p.wantSeq:
		p.wantSeq = h.PathSeq + 1
		p.stats.observeDelivered()
	}

	// The echo carries back timestamps we ourselves sent, along with how
	// long the peer sat on them. Subtracting that hold time leaves the
	// round trip, with no dependence on the two clocks agreeing.
	for _, e := range h.Echo {
		ep := s.pathLocked(e.PathID)
		round := protocol.MicrosSince(nowTS, e.TS)
		if round >= e.Delay {
			ep.rtt = round - e.Delay
		}
		ep.rttFloor.observe(now, ep.rtt)
		// The peer is reporting a packet it received on this path, so our
		// transmit direction is working as of now.
		ep.confirmedAt = now
		// A probe is confirmed when the peer reports having seen a packet
		// at least as large as the one sent, which answers the question
		// directly rather than inferring it from a timestamp.
		if ep.mtu.probing != 0 && int(e.MaxSeen) >= ep.mtu.probing-ipUDPOverhead {
			ep.mtu.confirmed = ep.mtu.probing
			ep.mtu.probing = 0
			ep.mtu.misses = 0
		}
	}

	// The peer's view of our own send direction. This is the measurement
	// that cannot be taken locally at all: a round trip cannot say which
	// direction the delay was in, and every other statistic here describes
	// packets arriving, not packets leaving.
	for _, r := range h.Reports {
		rp := s.pathLocked(r.PathID)
		rp.peer = peerView{
			spreadMs: float64(r.SpreadTenthMs) / 10,
			queueMs:  float64(r.QueueTenthMs) / 10,
			jitterMs: float64(r.JitterTenthMs) / 10,
			loss:     float64(r.LossPerMille) / 10,
			burst:    float64(r.BurstTenths) / 10,
			at:       now,
			valid:    true,
		}
	}
}

// metrics assembles what the scheduler evaluates, one entry per known
// path. It is taken under the lock and handed back by value so that
// evaluation - which sorts, scores and logs - never holds the lock the data
// path needs to send a packet.
func (s *session) metrics(now time.Duration) []pathMetric {
	s.mu.Lock()
	defer s.mu.Unlock()

	c := s.cfg.Get()
	managed := s.role == roleInitiator
	out := make([]pathMetric, 0, len(s.paths))
	for id, p := range s.paths {
		st := &p.stats

		// The bandwidth estimate is advanced here rather than on a loop of
		// its own. This is already the once-per-evaluation pass over every
		// path under the lock, it has the round trip and the receive-side
		// queue delay to hand, and giving the estimate its own goroutine
		// would only add a second cadence to keep in step with this one.
		p.bw.observe(now, ms(p.rtt), msi(st.queueDelay), p.peer, c)

		// A path that has never delivered anything has been silent for as
		// long as this process has been running. The initiator registers
		// every configured path at startup, so that is the truth for a
		// link that has never come up; the responder only learns a path
		// by hearing from it, so the case does not arise there.
		silent := now
		if st.received > 0 {
			silent = now - p.seenAt
		}

		out = append(out, pathMetric{
			id:             id,
			name:           s.names[id],
			managed:        managed,
			bound:          p.bound,
			silentFor:      silent,
			sentSinceHeard: p.sentSince,
			confirmedAt:    p.confirmedAt,
			rttMs:          ms(p.rtt),
			p95SpreadMs:    msi(st.spread()),
			jitterMs:       st.jitter / 1000,
			queueDelayMs:   msi(st.queueDelay),
			recentLoss:     st.recentLossPercent(),
			burstRatio:     st.recentBurstRatio(),
			thin:           st.thin(),
			unusable:       p.mtu.ceiling != 0 && p.mtu.confirmed < minUsablePathMTU,
			bw:             p.bw.view(now, c),

			haveTx:       p.peer.fresh(now),
			txSpreadMs:   p.peer.spreadMs,
			txQueueMs:    p.peer.queueMs,
			txJitterMs:   p.peer.jitterMs,
			txLoss:       p.peer.loss,
			txBurstRatio: p.peer.burst,
			rttFloorMs:   ms(p.rttFloor.cur),
		})
	}
	return out
}

// recommendedTunnelMTU is the inner MTU the discovered paths can carry,
// taken as the minimum across paths: a packet sized for a large path
// cannot be moved onto a small one, which would break steering at exactly
// the moment it is needed. Returns 0 until something has been confirmed.
func (s *session) recommendedTunnelMTU() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recommendedTunnelMTULocked()
}

// logStats reports what the measurement layer is seeing. Scaffolding until
// the state file and web UI land.
func (s *session) logStats() {
	var last time.Duration
	for range time.Tick(time.Second) {
		now := s.elapsed()
		if now-last < s.cfg.Get().StatsInterval() {
			continue
		}
		last = now

		d := emptyDecision
		if s.sched != nil {
			d = s.sched.current()
		}

		s.mu.Lock()
		for id, p := range s.paths {
			st := &p.stats
			log.Printf("path %d: %s | rtt %.1fms p95-spread %.1fms jitter %.1fms queue %.1fms | "+
				"rx %d lost %d bursts %v | samples %d%s | mtu %d | tx %.0fkbps %s",
				id, describe(d, id),
				ms(p.rtt), msi(st.spread()), st.jitter/1000, msi(st.queueDelay),
				st.received, st.lost, st.bursts,
				st.filled, thinNote(st.thin()),
				p.mtu.confirmed,
				p.bw.sendKbps, describeCeiling(&p.bw, now))
		}
		if d.blind {
			log.Printf("scheduler: %s", d.reason)
		}
		if mtu := s.recommendedTunnelMTULocked(); mtu != 0 {
			log.Printf("recommended tunnel mtu: %d", mtu)
		}
		if bad := s.unusablePathsLocked(); len(bad) > 0 {
			log.Printf("paths %v cannot carry the %d byte tunnel floor and are excluded",
				bad, minTunnelMTU)
		}
		s.mu.Unlock()
	}
}

// describeCeiling renders a path's capacity estimate for the log, in the
// terms it is actually held in: a ceiling that was measured, how long ago
// anything confirmed it, or the fact that nothing ever has.
func describeCeiling(b *bwEstimate, now time.Duration) string {
	switch {
	case b.haveCeiling:
		return fmt.Sprintf("ceiling %.0fkbps (confirmed %v ago)",
			b.ceilingKbps, (now - b.confirmedAt).Round(time.Second))
	case b.everLoaded:
		return fmt.Sprintf("ceiling unknown, carried %.0fkbps clean", b.provenKbps)
	}
	return "ceiling unknown, never loaded"
}

// recommendedTunnelMTULocked is recommendedTunnelMTU for callers already
// holding the lock.
//
// A path too small to carry the floor is left out of the minimum rather
// than dragging the tunnel below it. Clamping such a path up to the floor
// would be worse than useless: it would recommend an MTU the path has
// already demonstrated it cannot carry. Paths still being probed are also
// excluded, so an unmeasured path never silently shrinks the tunnel.
func (s *session) recommendedTunnelMTULocked() int {
	smallest := 0
	for _, p := range s.paths {
		if p.mtu.confirmed < minUsablePathMTU {
			continue
		}
		if smallest == 0 || p.mtu.confirmed < smallest {
			smallest = p.mtu.confirmed
		}
	}
	if smallest == 0 {
		return 0
	}
	return smallest - ipUDPOverhead - protocol.MaxDataHeaderLen - wireGuardOverhead
}

// unusablePathsLocked names the paths that have been probed and cannot
// carry the tunnel floor. These want flagging rather than accommodating.
func (s *session) unusablePathsLocked() []uint8 {
	var out []uint8
	for id, p := range s.paths {
		if p.mtu.ceiling != 0 && p.mtu.confirmed < minUsablePathMTU {
			out = append(out, id)
		}
	}
	return out
}

// aliveWithin is how recently a path must have delivered something to be
// called alive. It is deliberately several times the slowest report
// cadence, so a path is not declared dead for missing one.
const aliveWithin = 5 * time.Second

// snapshot renders the current measurements for the web interface.
func (s *session) snapshot(tunnelMTU int) state.Snapshot {
	now := s.elapsed()

	// Read the scheduler's verdict before taking the lock. It is an
	// immutable published value, so there is nothing to coordinate, and
	// reaching for it under the lock would be inviting a deadlock for no
	// benefit.
	d := emptyDecision
	if s.sched != nil {
		d = s.sched.current()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	snap := state.Snapshot{
		Node:                 s.node,
		Role:                 s.role,
		UpdatedUnix:          float64(time.Now().UnixNano()) / 1e9,
		UptimeSeconds:        now.Seconds(),
		TunnelMTU:            tunnelMTU,
		RecommendedTunnelMTU: s.recommendedTunnelMTULocked(),
		ManagesPaths:         s.role == roleInitiator,
		Config:               s.cfg.Get(),
	}

	ids := make([]uint8, 0, len(s.paths))
	for id := range s.paths {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	var best float64
	for _, id := range ids {
		p := s.paths[id]
		st := &p.stats

		lastSeen := math.Inf(1)
		alive := false
		if p.stats.received > 0 {
			lastSeen = (now - p.seenAt).Seconds()
			alive = now-p.seenAt < aliveWithin
		}

		path := state.Path{
			ID:                id,
			Name:              s.names[id],
			RTTMs:             ms(p.rtt),
			P95SpreadMs:       msi(st.spread()),
			JitterMs:          st.jitter / 1000,
			QueueDelayMs:      msi(st.queueDelay),
			Received:          st.received,
			Lost:              st.lost,
			RecentLossPercent: st.recentLossPercent(),
			LossPercent:       lossPercent(st.received, st.lost),
			Bursts:            burstsOf(st),
			Samples:           st.filled,
			Thin:              st.thin(),
			PathMTU:           p.mtu.confirmed,
			Usable:            p.mtu.confirmed >= minUsablePathMTU,
			LastSeenSeconds:   lastSeen,
			Alive:             alive,
		}

		// Read, never advanced: the estimate is driven from the evaluation
		// pass in metrics, and the state file is written on a cadence of its
		// own. Sampling it here as well would fold the same bytes in twice
		// and report a rate that moved with how often the interface was
		// being looked at.
		if p.peer.fresh(now) {
			path.TxReported = true
			path.TxSpreadMs = p.peer.spreadMs
			path.TxQueueDelayMs = p.peer.queueMs
			path.TxJitterMs = p.peer.jitterMs
			path.TxLossPercent = p.peer.loss
			path.TxDelayMs = outboundDelayMs(ms(p.rttFloor.cur), p.peer.spreadMs,
				float64(snap.Config.BaseDelayMs))
		}
		path.RTTFloorMs = ms(p.rttFloor.cur)

		bw := p.bw.view(now, snap.Config)
		path.SendKbps = bw.sendKbps
		path.PeakKbps = bw.peakKbps
		path.ProvenKbps = bw.provenKbps
		path.CeilingKbps = bw.ceilingKbps
		path.CeilingKnown = bw.haveCeiling
		path.LimitKbps = bw.limitKbps
		path.CeilingAgeSeconds = -1
		if bw.everLoaded {
			path.CeilingAgeSeconds = (now - bw.confirmedAt).Seconds()
		}
		if v, ok := d.views[id]; ok {
			path.State = v.State
			path.StateReason = v.Reason
			path.RFactor = v.RFactor
			path.Score = v.Score
			path.MOS = v.MOS
			path.Flapping = v.Flapping
			path.Transitions = v.Transitions
			path.Sending = v.Sending
			path.Primary = d.havePrimary && d.primary == id
		}
		if snap.ManagesPaths {
			path.Bound = p.bound
			path.Local = p.local
			path.Drops = p.drops
		}
		if p.remote != nil {
			path.Remote = p.remote.String()
		}
		if math.IsInf(lastSeen, 1) {
			path.LastSeenSeconds = -1 // never heard from
		}
		snap.Paths = append(snap.Paths, path)

		snap.Aggregate.Received += st.received
		snap.Aggregate.Lost += st.lost
		if alive {
			snap.Aggregate.PathsAlive++
			if rtt := ms(p.rtt); rtt > 0 && (best == 0 || rtt < best) {
				best = rtt
			}
		}
	}

	// The aggregate recent rate is taken across the same windows as the
	// per-path ones rather than averaged from them, so a busy path counts
	// for more than an idle one.
	var winRecv, winLost uint64
	for _, id := range ids {
		st := &s.paths[id].stats
		winRecv += st.winRecv + st.prevRecv
		winLost += st.winLost + st.prevLost
	}
	snap.Aggregate.RecentLossPercent = lossPercent(winRecv, winLost)

	snap.Aggregate.PathsTotal = len(ids)
	snap.Aggregate.BestRTTMs = best
	snap.Aggregate.LossPercent = lossPercent(snap.Aggregate.Received, snap.Aggregate.Lost)

	snap.Scheduler = state.Scheduler{
		Primary:       -1,
		SwitchingTo:   -1,
		Switching:     d.switching,
		Blind:         d.blind,
		Reason:        d.reason,
		DuplicateMode: snap.Config.DuplicateMode,
		Ranking:       d.ranking,
	}
	if d.havePrimary {
		snap.Scheduler.Primary = int(d.primary)
	}
	if d.switching {
		snap.Scheduler.SwitchingTo = int(d.switchingTo)
	}
	return snap
}

// lossPercent expresses loss against everything that was meant to arrive,
// which is what did arrive plus what did not.
func lossPercent(received, lost uint64) float64 {
	total := received + lost
	if total == 0 {
		return 0
	}
	return float64(lost) / float64(total) * 100
}

func burstsOf(st *pathStats) []state.Burst {
	out := make([]state.Burst, 0, len(st.bursts))
	for i, n := range st.bursts {
		// There is one more bucket than there are boundaries: the last
		// one catches every run longer than the largest named size, and
		// has no boundary of its own to be labelled with.
		label := fmt.Sprintf(">%d", burstBuckets[len(burstBuckets)-1])
		if i < len(burstBuckets) {
			label = fmt.Sprintf("<=%d", burstBuckets[i])
		}
		out = append(out, state.Burst{Label: label, Count: n})
	}
	return out
}

// writeState keeps the state file current for the web interface.
func (s *session) writeState(path, wgInterface string) {
	var last time.Duration
	for range time.Tick(100 * time.Millisecond) {
		if now := s.elapsed(); now-last < s.cfg.Get().StateInterval() {
			continue
		} else {
			last = now
		}
		if err := state.Write(path, s.snapshot(readInterfaceMTU(wgInterface))); err != nil {
			log.Printf("state: write to %s failed: %v", path, err)
		}
	}
}

// clockSane is the earliest wall-clock time a recorded timestamp is
// believed. A box with no RTC comes up in 1970 and only learns the real
// time once NTP completes over whatever link registers first, which on a
// cold boot in a campground can be minutes.
//
// Measurement itself needs none of this - every delay figure is relative
// to a process-local clock and the two ends share no epoch - so nothing is
// lost by waiting. What would be lost is the history: records stamped
// 1970 cannot be lined up against anything, and a drive whose first ten
// minutes claim to predate the last one is worse than a drive missing
// them.
var clockSane = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

// recordHistory appends a snapshot to the history log on a cadence of its
// own, so a drive leaves behind a file that can be looked at afterwards.
//
// A failure to write is logged and the loop continues. History is
// valuable, but not so valuable that losing the disk should take the
// tunnel down with it.
func (s *session) recordHistory(w *record.Writer, wgInterface string) {
	var last time.Duration
	waiting, failed := false, false

	for range time.Tick(time.Second) {
		now := s.elapsed()
		if now-last < s.cfg.Get().RecordInterval() {
			continue
		}
		if time.Now().Before(clockSane) {
			if !waiting {
				log.Printf("record: holding off, system clock reads %s and is not yet believable",
					time.Now().Format(time.RFC3339))
				waiting = true
			}
			continue
		}
		if waiting {
			log.Printf("record: clock now reads %s, recording history", time.Now().Format(time.RFC3339))
			waiting = false
		}
		last = now

		if err := w.Write(s.snapshot(readInterfaceMTU(wgInterface))); err != nil {
			if !failed {
				log.Printf("record: write failed, continuing without history: %v", err)
				failed = true
			}
			continue
		}
		failed = false
	}
}

// readInterfaceMTU reports what the tunnel interface is actually set to,
// so the interface can show the configured MTU beside the measured
// recommendation. Returns 0 if it cannot be read.
func readInterfaceMTU(name string) int {
	b, err := os.ReadFile("/sys/class/net/" + name + "/mtu")
	if err != nil {
		return 0
	}
	mtu, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0
	}
	return mtu
}

func ms(micros uint32) float64 { return float64(micros) / 1000 }
func msi(micros int32) float64 { return float64(micros) / 1000 }

func thinNote(thin bool) string {
	if thin {
		return " (thin)"
	}
	return ""
}

// describe renders a path's scheduling verdict for the log line, so that
// reading the journal answers "which path was carrying the call and why"
// without cross-referencing anything.
func describe(d *decision, id uint8) string {
	v, ok := d.views[id]
	if !ok {
		return "unscheduled"
	}
	out := v.State
	if v.Reason != "" {
		out += " (" + v.Reason + ")"
	}
	out += fmt.Sprintf(" mos %.1f", v.MOS)
	switch {
	case d.havePrimary && d.primary == id:
		out += " PRIMARY"
	case v.Sending:
		out += " sending"
	}
	if v.Flapping {
		out += " FLAPPING"
	}
	return out
}
