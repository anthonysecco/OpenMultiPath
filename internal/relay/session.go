package relay

import (
	"errors"
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
	"github.com/anthonysecco/OpenMultiPath/internal/usage"
)

// The two ends run the same session code and differ only in role. The
// initiator owns the physical sockets and so has paths that can be bound
// or not; the responder learns its paths from whatever arrives.
const (
	roleInitiator = "initiator"
	roleResponder = "responder"
)

// usageSampleInterval is how often the kernel's byte counters are folded
// into the billing-cycle totals and written to disk.
const usageSampleInterval = 30 * time.Second

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
// again from scratch - but only for a path that has never confirmed a
// usable size (see buildProbe). A path that has found its MTU does not
// re-probe on this timer at all; the one thing that can change its MTU is a
// reconnect, which arrives as a down/up transition and restarts the search
// through rearmMTU.
//
// Three misses at the default cadence is ~45s, which a real dead zone
// clears easily - the scenario walkthrough in scope-v1.md has these running
// to minutes. Without a retry, a ceiling set during an ordinary outage
// would never be reconsidered on a path that never came up cleanly:
// confirmed stays 0 forever, the path reads as unable to carry the tunnel
// floor, and only a daemon restart clears it. That is exactly backwards for
// a project whose premise is that links come back.
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
	meter sendMeter

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

	// bulkRxAt is when a flow-sequenced bulk packet last arrived here, which
	// means the far end is spreading bulk and pacing it on what we report.
	// lastFastReport is when we last reported for that reason. See
	// fastReportDue.
	bulkRxAt       time.Duration
	lastFastReport time.Duration
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

	// Version 3: the standing queue and loss over the last second.
	standingMs float64
	shortLoss  float64
	rxKbps     float64 // what the peer received on this path over the last second

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

// rttFloorWindow is long enough that a standing queue is not absorbed into
// the baseline, which is the whole reason the floor is being kept.
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
	// classCounts is indexed by protocol class, so a packet's class is
	// its own counter's index. Sized to the three that exist.
	classCounts [4]atomic.Uint64

	// withheldBulk counts packets admission control dropped. Without it a
	// starved link and an idle one read identically from a campground, the
	// same trap the class counters exist for.
	withheldBulk atomic.Uint64

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

	// classifier is step 7, set once before the relay starts, read only
	// for the flow dump in the snapshot. Zero value is a no-op classifier
	// (see flowClassifier), same as when payloads are ciphertext below
	// WireGuard.
	classifier flowClassifier

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

	mu    sync.Mutex
	paths map[uint8]*pathState
	names map[uint8]string

	// dedup drops the second copy of a duplicated packet. See dedup.go:
	// below WireGuard the replay window underneath did this for free, and
	// D-020 took that away.
	dedup *dedupWindow

	// dropped counts the copies it discarded, which is how much
	// duplication actually cost. Worth a number rather than an
	// inference: it is the difference between "redundancy is protecting
	// the call" and "redundancy is being paid for and thrown away".
	dupDropped atomic.Uint64

	// meter accounts for what each link has carried this billing cycle.
	// Nil on the responder, which owns no interfaces and whose traffic is
	// not billed to this vehicle - and nil is a working state, not a
	// missing one: every path then reads unmetered and green, which is
	// exactly right for a link with no allowance to spend.
	meter      *usage.Meter
	lastEcho   time.Duration
	lastReport time.Duration

	// reseq puts bulk the far end spread across paths back in order before
	// delivery (v0.2). Nil in tests that exercise measurement alone, where
	// payloads are written straight through.
	reseq *resequencer

	// flowSeqs is the next flow sequence for each bucket. Touched only by
	// the one goroutine reading the local endpoint, so it needs no lock:
	// allocation happens once per packet there, before any copies are made.
	flowSeqs [protocol.FlowBuckets]uint32

	// writePath puts a finished packet on a path, and throughWireGuard says
	// whether that path is a WireGuard interface, which decides what the
	// packet costs the link. Both set once before anything is sent; see
	// setPathWriter.
	writePath        func(id uint8, pkt []byte)
	throughWireGuard bool

	// shapers hold each path to its measured speed (D-055). Created on first
	// use and never removed, so the data path reads them without a lock.
	shapers [256]atomic.Pointer[pathShaper]

	// The measured link speeds, under mu (D-055, linkspeed.go). The vehicle
	// takes them from its measurement file and home from the vehicle.
	// speedsAcked and speedPayload are the vehicle's side of telling home:
	// whether home has acknowledged the set held, and the set as sent.
	speeds        map[uint8]protocol.LinkSpeed
	speedDigest   uint32
	haveSpeeds    bool
	speedsAcked   bool
	lastSpeedSent time.Duration
	speedPayload  []byte
}

func newSession(cfg *config.Holder, node, role string) *session {
	if cfg == nil {
		cfg = config.NewHolder(config.Defaults())
	}
	s := &session{
		start:  time.Now(),
		cfg:    cfg,
		node:   node,
		role:   role,
		paths:  make(map[uint8]*pathState),
		names:  make(map[uint8]string),
		dedup:  newDedupWindow(),
		speeds: make(map[uint8]protocol.LinkSpeed),
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
// stamp builds one data packet, carrying the class the caller already
// decided for it.
//
// The class is passed in rather than worked out here on purpose. A packet
// that goes out several paths calls this once per copy, so classifying
// inside would repeat the work - and worse, could hand two copies of the
// same packet different classes if the flow's verdict settled in between.
// One packet, one class, whatever it costs to deliver.
// noteClass records what step 7 decided about one packet.
//
// Counters rather than a log line per packet, and atomic rather than under
// the session mutex, because this runs on every packet the daemon carries
// and the mutex is already the busiest lock in it.
//
// They exist to make the classifier answerable in the field. "No real-time
// traffic was seen" and "classification is not running" produce identical
// path statistics, and telling them apart from a campground otherwise
// means reading source.
// deliver reports whether an arriving data packet is the first copy, and
// counts it when it is not.
func (s *session) deliver(seq uint32) bool {
	if s.dedup.accept(seq) {
		return true
	}
	s.dupDropped.Add(1)
	return false
}

// noteWithheld records a packet admission control refused to send.
func (s *session) noteWithheld() { s.withheldBulk.Add(1) }

func (s *session) noteClass(class uint8) {
	if int(class) < len(s.classCounts) {
		s.classCounts[class].Add(1)
	}
}

// classTotals reads the counters back for the log and the interface.
func (s *session) classTotals() (realtime, transactional, bulk, unknown uint64) {
	return s.classCounts[protocol.ClassRealtime].Load(),
		s.classCounts[protocol.ClassTransactional].Load(),
		s.classCounts[protocol.ClassBulk].Load(),
		s.classCounts[protocol.ClassUnknown].Load()
}

func (s *session) stamp(pathID uint8, globalSeq uint32, class uint8, payload, buf []byte) []byte {
	return s.buildWith(protocol.TypeData, pathID, globalSeq, class, flowTag{}, payload, buf, nil)
}

// flowTag is one bulk packet's place in its flow's sequence (v0.2). The zero
// value is written as bucket 0, sequence 0 on a version 3 bulk packet, so the
// data path must always stamp bulk through stampFlow with a tag from
// nextFlowTag.
type flowTag struct {
	bucket uint16
	seq    uint32
}

// nextFlowTag allocates the flow sequence for one bulk packet, from the flow
// hash the scheduler already computed. Called once per packet, after the
// decision to send it and before any copies: a sequence allocated for a
// packet that was then dropped would leave a gap the far end had to wait out.
func (s *session) nextFlowTag(flow uint32) flowTag {
	b := uint16(flow % protocol.FlowBuckets)
	seq := s.flowSeqs[b]
	s.flowSeqs[b] = (seq + 1) & protocol.FlowSeqMask
	return flowTag{bucket: b, seq: seq}
}

// stampFlow is stamp for the data path, carrying the flow tag a version 3
// bulk packet needs. Every copy of one packet takes the same tag.
func (s *session) stampFlow(pathID uint8, globalSeq uint32, class uint8, tag flowTag, payload, buf []byte) []byte {
	return s.buildWith(protocol.TypeData, pathID, globalSeq, class, tag, payload, buf, nil)
}

// deliverData hands an arriving data payload on: dropped if it is a copy
// already delivered, resequenced if it is spread bulk, written straight
// through otherwise.
func (s *session) deliverData(h *protocol.Header, payload []byte, write func([]byte) error) error {
	if !s.deliver(h.GlobalSeq) {
		return nil
	}
	if h.HasFlow && s.reseq != nil {
		s.reseq.push(h.PathID, h.FlowBucket, h.FlowSeq, payload)
		return nil
	}
	return write(payload)
}

// build is for the packets that are not user traffic. Probes and reports
// carry no flow to classify and nothing downstream would act on a class,
// so they go out unclassified.
func (s *session) build(typ, pathID uint8, globalSeq uint32, payload, buf []byte) []byte {
	return s.buildWith(typ, pathID, globalSeq, protocol.ClassUnknown, flowTag{}, payload, buf, nil)
}

func (s *session) buildWith(typ, pathID uint8, globalSeq uint32, class uint8, tag flowTag, payload, buf []byte, reports []protocol.ReportEntry) []byte {
	now := s.elapsed()

	s.mu.Lock()
	p := s.pathLocked(pathID)
	h := protocol.Header{
		Type:      typ,
		Class:     class,
		PathID:    pathID,
		GlobalSeq: globalSeq,
		PathSeq:   p.nextSeq,
		SendTS:    uint32(now.Microseconds()),
		Reports:   reports,

		FlowBucket: tag.bucket,
		FlowSeq:    tag.seq,
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

	// Built under the lock so the send meter can count what actually went
	// onto the wire rather than an estimate of it. The header's length
	// varies with how many echo entries rode along, and a rate derived from
	// a guess at that would be wrong in exactly the direction that matters:
	// echoes are largest when the most paths need reporting on.
	out := append(h.AppendTo(buf[:0], s.emitVersion(), s.authKey), payload...)
	p.meter.note(s.wireBytes(len(out)))
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
	return s.buildReportWith(pathID, buf, false)
}

// buildReportWith is buildReport, and when fast is set it carries path
// reports whatever the ordinary report cadence says - see fastReportDue.
func (s *session) buildReportWith(pathID uint8, buf []byte, fast bool) []byte {
	now := s.elapsed()

	var reports []protocol.ReportEntry
	if s.emitVersion() >= 2 {
		s.mu.Lock()
		if fast || now-s.lastReport >= s.cfg.Get().ReportInterval() {
			reports = s.collectReportsLocked(now)
			if len(reports) > 0 {
				s.lastReport = now
			}
		}
		if fast {
			s.pathLocked(pathID).lastFastReport = now
		}
		s.mu.Unlock()
	}

	return s.buildWith(protocol.TypeReport, pathID, s.nextGlobalSeq(), protocol.ClassUnknown, flowTag{}, nil, buf, reports)
}

// fastReportWindow is how long after the last spread bulk packet a path keeps
// reporting at the fast cadence.
const fastReportWindow = 2 * time.Second

// fastReportDue reports whether a path should carry a report now because the
// far end is spreading bulk onto it (v0.2-design.md, section 6).
//
// The far end paces bulk on what we report about its send direction, and the
// ordinary rule defeats that twice over: reports go out once a second, and
// only on a path idle enough to have no data to ride. A path carrying spread
// bulk is by definition never idle. So while bulk is arriving on a path, a
// report goes out on it at the cascade cadence regardless. One report covers
// every path, so sending on each bulk-carrying path is redundancy against
// loss rather than repetition.
func (s *session) fastReportDue(id uint8) bool {
	if s.emitVersion() < 3 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.elapsed()
	p := s.pathLocked(id)
	if p.bulkRxAt == 0 || now-p.bulkRxAt > fastReportWindow {
		return false
	}
	return now-p.lastFastReport >= s.cfg.Get().CascadeReportInterval()
}

// collectReportsLocked describes what we have measured on the peer's
// transmissions, one entry per path we have heard anything on.
//
// It reports on paths rather than on recent arrivals, unlike the echo
// block: a path that has gone quiet is exactly the one the peer most needs
// told about, because silence at this end is how its send direction failing
// looks from here.
func (s *session) collectReportsLocked(now time.Duration) []protocol.ReportEntry {
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

			StandingQueueTenthMs: tenthMs(msi(st.standingQueue(now))),
			ShortLossPerMille:    perMille(st.shortLossPercent(now)),
			RxKbpsBy16:           by16(st.shortRxKbps(now)),
		})
	}
	return out
}

// by16 converts kbps to the wire's 16 kbps units, saturating.
func by16(kbps float64) uint16 {
	v := kbps / 16
	switch {
	case v < 0:
		return 0
	case v > math.MaxUint16:
		return math.MaxUint16
	}
	return uint16(v + 0.5)
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
	if p.mtu.ceiling != 0 && p.mtu.confirmed < minUsablePathMTU &&
		now-p.mtu.ceilingAt >= mtuCeilingRetryAfter {
		// Retry only while the path has never found a size it can carry.
		//
		// A path that has confirmed a usable MTU is done: re-probing a
		// stable link on a timer is management traffic on an idle path,
		// spent on a number that does not change (D-039). What can change
		// it - a reconnect onto a different bearer with a smaller MTU - comes
		// back as a down/up transition, and rearmMTU restarts the search
		// from scratch then.
		//
		// A path still stuck below the floor is the case the retry exists
		// for: giving up permanently would strand a link that an outage,
		// not a small MTU, put here - confirmed would sit at 0 forever and
		// only a restart would clear it. That is the one place a timer is
		// still worth its packets.
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
		p.meter.note(pad)
		s.mu.Unlock()
	}
	return out
}

// rearmMTU restarts a path's MTU search from scratch. The scheduler calls
// it when a path comes up from down, which is the one moment its MTU can
// have changed without anyone probing for it: a link that dropped and
// reconnected may have come back on a different bearer - 5G to LTE, one
// tower to the next - with a smaller MTU, and a packet still sized for the
// old one would black-hole (D-039).
//
// confirmed is reset to zero rather than kept, precisely so a shrink is
// caught: keeping the old, larger value would be the black hole. The path
// is coming up from down, so it was carrying nothing to lose in the
// meantime, and recommendedTunnelMTU already excludes a path whose
// confirmed size is below the floor - so a path mid-re-search does not drag
// the tunnel MTU down with it.
func (s *session) rearmMTU(id uint8) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pathLocked(id).mtu = mtuProbe{}
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
			switch {
			case s.fastReportDue(id):
				send(id, s.buildReportWith(id, buf, true))
			case s.dueForReport(id):
				send(id, s.buildReport(id, buf))
			}
		}

		// A changed set of link speeds goes home on every path at once,
		// repeated until home acknowledges it (D-055). One copy getting
		// through is enough.
		if payload := s.linkSpeedDue(now); payload != nil {
			for _, id := range pathIDs() {
				send(id, s.build(protocol.TypeLinkSpeed, id, s.nextGlobalSeq(), payload, buf))
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

		// Its flow sequences started again too.
		if s.reseq != nil {
			s.reseq.reset()
		}

		// And it has forgotten the link speeds it was told, so they are
		// due again (D-055).
		s.speedsAcked = false
	}
	p.stats.noteBytes(wireLen)
	if h.HasFlow {
		p.bulkRxAt = now
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

			standingMs: float64(r.StandingQueueTenthMs) / 10,
			shortLoss:  float64(r.ShortLossPerMille) / 10,
			rxKbps:     float64(r.RxKbpsBy16) * 16,
			valid:      true,
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

		// The send meter is advanced here rather than on a loop of its own:
		// this is already the once-per-evaluation pass over every path under
		// the lock, and a second cadence would only need keeping in step.
		p.meter.observe(now)

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
			sendKbps:       p.meter.kbps,
			shapedKbps:     s.shapedKbpsLocked(id),
			budget:         s.budgetState(s.names[id], c),
			label:          c.LabelFor(s.names[id]),

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

// holdLiveWindow is how recently a path must have delivered anything to
// count toward the resequencer's hold.
const holdLiveWindow = 2 * time.Second

// holdTailCapMs caps how much of a path's measured tail the hold waits out.
// It was the cascade's queue target, 40 ms, when the cascade paced on queue
// (D-052); with paths shaped under their measured speed (D-055) the carrier's
// queue should stay shorter than that, and a tail beyond it is a spike the
// resequencer should not stall every flow for.
const holdTailCapMs = 40

// updateHold sets how long the resequencer waits for a missing packet, from
// this end's own inbound measurements (v0.2-design.md, section 7).
//
// The receiver is measuring exactly the direction it is resequencing, so
// nothing needs to come over the wire and no clocks need to agree. The wait
// a gap deserves is how far behind the fastest path the slowest can deliver:
// the difference in their base delays, plus the queue that stands on a path -
// the smaller of the worst tail measured and holdTailCapMs - plus a margin,
// capped.
//
// Every live path counts, not only those already carrying spread bulk. The
// hold has to be right before the far end spills onto a second path, not an
// evaluation after: the lab run that found this delivered its first few
// hundred spilled packets late while the hold was still sized for one path.
func (s *session) updateHold(now time.Duration, c config.Config) {
	if s.reseq == nil {
		return
	}
	s.mu.Lock()
	slowest, fastest, tail, n := 0.0, math.Inf(1), 0.0, 0
	for _, p := range s.paths {
		if p.stats.received == 0 || now-p.seenAt > holdLiveWindow || !p.rttFloor.have {
			continue
		}
		base := ms(p.rttFloor.cur) / 2
		if base > slowest {
			slowest = base
		}
		if base < fastest {
			fastest = base
		}
		if t := msi(p.stats.spread()); t > tail {
			tail = t
		}
		n++
	}
	s.mu.Unlock()

	hold := c.ResequencerHoldMargin()
	if n > 1 {
		if tail > holdTailCapMs {
			tail = holdTailCapMs
		}
		hold += time.Duration((slowest - fastest + tail) * float64(time.Millisecond))
	}
	s.reseq.setPredictedHold(hold, c.ResequencerMaxHold())
}

// budgetFor turns the configured allowance for an interface into the form
// the accounting wants.
func budgetFor(iface string, c config.Config) usage.Budget {
	l := c.LinkFor(iface)
	return usage.Budget{
		CapBytes:             uint64(l.CapMB) << 20,
		CycleDay:             l.CycleDay,
		GreenHeadroomPercent: c.BudgetGreenHeadroomPercent,
	}
}

// cycleStartUnix is the billing cycle's start as a unix time, or zero
// when nothing is being accounted for this link.
func cycleStartUnix(u usage.State) float64 {
	if u.CycleStart.IsZero() {
		return 0
	}
	return float64(u.CycleStart.UnixNano()) / 1e9
}

// budgetState is what this link has spent, or the unmetered zero value
// where nothing is being accounted.
func (s *session) budgetState(iface string, c config.Config) usage.State {
	if s.meter == nil || iface == "" {
		return usage.State{}
	}
	return s.meter.State(iface, budgetFor(iface, c), time.Now())
}

// trackUsage folds the kernel's interface counters into each link's cycle
// total, and persists them.
//
// Slow on purpose. The counters are monotonic, so nothing is lost by
// reading them a minute apart, and the figure this feeds is a projection
// across a month - a cadence that mattered to it would be a cadence that
// could not survive the daemon being restarted. Persisting matters more
// than sampling often: scope-v1.md is explicit that losing these on a
// power cycle means relearning at exactly the moment the RV is moving.
func (s *session) trackUsage() {
	for range time.Tick(usageSampleInterval) {
		c := s.cfg.Get()
		now := time.Now()
		for _, name := range s.pathNames() {
			if name == "" {
				continue
			}
			s.meter.Sample(name, budgetFor(name, c), now)
		}
		if err := s.meter.Save(); err != nil {
			log.Printf("usage: saving cycle totals failed: %v", err)
		}
	}
}

// pathNames is the interfaces currently registered, copied out under the
// lock so the sampling loop never holds it while reading /sys.
func (s *session) pathNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.names))
	for _, n := range s.names {
		out = append(out, n)
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
			log.Printf("%s: %s | rtt %.1fms p95-spread %.1fms jitter %.1fms queue %.1fms | "+
				"rx %d lost %d bursts %v | samples %d%s | mtu %d | tx %.0fkbps | %s",
				pathLabel(id, s.cfg.Get().LabelFor(s.names[id])), describe(d, id),
				ms(p.rtt), msi(st.spread()), st.jitter/1000, msi(st.queueDelay),
				st.received, st.lost, st.bursts,
				st.filled, thinNote(st.thin()),
				p.mtu.confirmed,
				p.meter.kbps, s.describeShapingLocked(id))
		}
		if d.blind {
			log.Printf("scheduler: %s", d.reason)
		}
		if rt, tx, bulk, unk := s.classTotals(); rt+tx+bulk+unk > 0 {
			log.Printf("traffic: %d real-time, %d transactional, %d bulk, %d unclassified",
				rt, tx, bulk, unk)
		}
		if n := s.dupDropped.Load(); n > 0 {
			log.Printf("duplication: %d redundant copies discarded on arrival", n)
		}
		if w := s.withheldBulk.Load(); w > 0 {
			log.Printf("admission: %d bulk packets withheld to protect the call", w)
		}
		if s.sched != nil {
			// Named from the session's own table rather than the scheduler's,
			// which belongs to the evaluation goroutine.
			name := func(id uint8) string { return pathLabel(id, s.cfg.Get().LabelFor(s.names[id])) }
			log.Printf("bulk: %s; %d sent past every allowance", describeCascade(d, name), s.sched.overflowed.Load())
		}
		if s.reseq != nil {
			if st := s.reseq.stats(); st.Reordered > 0 || st.Late > 0 {
				log.Printf("resequencer: hold %.0fms, %d held now, %d reordered, %d late, gaps given up %d lost / %d timed out / %d forced",
					st.HoldMs, st.Buffered, st.Reordered, st.Late, st.GapsLost, st.GapsTimedOut, st.GapsForced)
			}
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

// describeShapingLocked renders a path's measured speed and shaping for the
// log.
func (s *session) describeShapingLocked(id uint8) string {
	shaped := s.shapedKbpsLocked(id)
	if shaped <= 0 {
		return "link speed unmeasured, unshaped"
	}
	out := fmt.Sprintf("measured %s, shaped to %s", kbpsText(s.localKbpsLocked(id)), kbpsText(shaped))
	if sh := s.shapers[id].Load(); sh != nil {
		if b := sh.backlog(); b > 0 {
			out += fmt.Sprintf(", %d bytes queued", b)
		}
		if d := sh.dropped.Load(); d > 0 {
			out += fmt.Sprintf(", %d dropped at the queue limit", d)
		}
	}
	return out
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

	c := s.cfg.Get()

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
		Config:               c,
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

		budget := s.budgetState(s.names[id], c)
		path := state.Path{
			ID:                id,
			Name:              s.names[id],
			Label:             labelOrEmpty(snap.Config, s.names[id]),
			Budget:            budget.Band.String(),
			BudgetMetered:     budget.Metered,
			CapBytes:          budgetFor(s.names[id], c).CapBytes,
			UsedBytes:         budget.Bytes,
			ProjectedBytes:    budget.Projected,
			CycleStartUnix:    cycleStartUnix(budget),
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

		if p.peer.fresh(now) {
			path.TxReported = true
			path.TxSpreadMs = p.peer.spreadMs
			path.TxQueueDelayMs = p.peer.queueMs
			path.TxJitterMs = p.peer.jitterMs
			path.TxLossPercent = p.peer.loss
			path.TxStandingQueueMs = p.peer.standingMs
			path.TxShortLossPercent = p.peer.shortLoss
			path.TxDelayMs = outboundDelayMs(ms(p.rttFloor.cur), p.peer.spreadMs,
				float64(snap.Config.BaseDelayMs))
		}
		path.RTTFloorMs = ms(p.rttFloor.cur)

		// Read, never advanced: the meter is driven from the evaluation pass
		// in metrics, and the state file is written on a cadence of its own.
		// Sampling it here as well would fold the same bytes in twice and
		// report a rate that moved with how often the interface was being
		// looked at.
		path.SendKbps = p.meter.kbps
		if ls, ok := s.speeds[id]; ok {
			path.LinkUpKbps = float64(ls.UpKbps)
			path.LinkDownKbps = float64(ls.DownKbps)
			path.LinkMeasuredUnix = int64(ls.MeasuredUnix)
		}
		path.ShapedKbps = s.shapedKbpsLocked(id)
		if sh := s.shapers[id].Load(); sh != nil {
			path.ShaperBacklogBytes = sh.backlog()
			path.ShaperDropped = sh.dropped.Load()
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
		path.CascadePosition = -1
		for i, m := range d.cascade {
			if d.cascadeOn && m.id == id {
				path.CascadePosition = i
				path.CascadeProtected = m.protected
				path.BulkKbps = m.sentKbps
			}
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
		Primary:         -1,
		SwitchingTo:     -1,
		Switching:       d.switching,
		Blind:           d.blind,
		WithholdingBulk: d.withholdBulk,
		WithheldBulk:    s.withheldBulk.Load(),
		BulkPath:        -1,
		Reason:          d.reason,
		DuplicateMode:   snap.Config.DuplicateMode,
		Ranking:         d.ranking,
	}
	if d.havePrimary {
		snap.Scheduler.Primary = int(d.primary)
	}
	if d.switching {
		snap.Scheduler.SwitchingTo = int(d.switchingTo)
	}
	snap.Scheduler.ClassRealtime, snap.Scheduler.ClassTransactional,
		snap.Scheduler.ClassBulk, snap.Scheduler.ClassUnknown = s.classTotals()
	snap.Scheduler.Classifying = s.classifier.enabled()
	snap.Scheduler.DuplicatesDropped = s.dupDropped.Load()
	// Bulk rides exactly one path once it has been steered; more than one
	// only happens in blind mode, where the distinction has stopped
	// meaning anything.
	if len(d.txBulk) == 1 && !d.blind {
		snap.Scheduler.BulkPath = int(d.txBulk[0])
	}
	snap.Scheduler.BulkScheduler = config.BulkFlow
	if d.cascadeOn {
		snap.Scheduler.BulkScheduler = config.BulkCascade
	} else {
		snap.Scheduler.BulkSchedulerReason = d.cascadeWhy
	}
	if s.sched != nil {
		snap.Scheduler.BulkOverflowed = s.sched.overflowed.Load()
	}
	snap.Scheduler.WireVersion = int(s.emitVersion())
	snap.LinkSpeedsHeld = s.haveSpeeds && len(s.speeds) > 0
	snap.LinkSpeedsAcknowledged = s.role == roleInitiator && s.speedsAcked
	if s.reseq != nil {
		snap.Scheduler.Resequencer = s.reseq.stats()
	}

	for _, f := range s.classifier.snapshot(time.Now()) {
		snap.Flows = append(snap.Flows, state.Flow{
			A:               f.A.String(),
			APort:           f.APort,
			B:               f.B.String(),
			BPort:           f.BPort,
			Proto:           flowProtoName(f.Proto),
			Class:           protocol.ClassName(f.Class),
			Decided:         f.Decided,
			Bytes:           f.Bytes,
			Samples:         f.Samples,
			LastSeenSeconds: f.LastSeenSeconds,
		})
	}

	return snap
}

// flowProtoName names the two protocols the classifier ever sees a flow
// for; anything else would mean parse() started admitting protocols it
// does not today.
func flowProtoName(proto uint8) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return fmt.Sprintf("%d", proto)
	}
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

// stateLockRetry is how often a daemon that lost the state file tries for
// it again, and stateLockRemind how often it says so in the log.
const (
	stateLockRetry  = 30 * time.Second
	stateLockRemind = 5 * time.Minute
)

// holdStateLock returns once this process owns the right to write path.
//
// A daemon that loses the race keeps relaying and keeps retrying rather
// than exiting. The state file is the instrument, not the job, and
// principle 5 asks for a box that still carries traffic when a part of it
// is broken. Retrying also means the survivor picks the file up by itself
// once whatever else was holding it goes away, with no restart and no
// trip to the vehicle.
//
// It reminds the log on a slow cadence instead of saying this once at
// startup. The whole failure being guarded against is invisible from a
// distance, and a single line written when the daemon started is not in
// the window an operator looks at once they finally notice.
func holdStateLock(path string) *state.Lock {
	var waited, nextRemind time.Duration
	for {
		lock, err := state.TryLock(path)
		if err == nil {
			if waited > 0 {
				log.Printf("state: %s came free after %s; writing it again",
					path, waited.Round(time.Second))
			}
			return lock
		}
		if waited >= nextRemind {
			if errors.Is(err, state.ErrLocked) {
				log.Printf("state: another ompd is already writing %s, so this one is not. "+
					"Traffic is unaffected, but the web interface is showing that daemon's "+
					"view of the world and not this one's. Find it with: pgrep -a '^ompd'", path)
			} else {
				log.Printf("state: cannot lock %s: %v; retrying", path, err)
			}
			nextRemind = waited + stateLockRemind
		}
		time.Sleep(stateLockRetry)
		waited += stateLockRetry
	}
}

// writeState keeps the state file current for the web interface.
func (s *session) writeState(path, wgInterface string) {
	// One writer per state file, or the two views interleave into
	// something that reads as a link fault. See state.Lock.
	lock := holdStateLock(path)
	defer lock.Close()

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
