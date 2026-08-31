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
	"github.com/anthonysecco/OpenMultiPath/internal/state"
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
	minUsablePathMTU = minTunnelMTU + ipUDPOverhead + protocol.MaxHeaderLen + wireGuardOverhead
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

// mtuProbe tracks the path MTU search for one path. Sizes are physical
// MTUs: what the link carries including the outer IP and UDP headers.
type mtuProbe struct {
	confirmed int // largest size confirmed to arrive
	probing   int // size currently outstanding, 0 when idle
	sentAt    time.Duration
	misses    int
	ceiling   int // sizes at or above this have failed; stop reaching
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

	rtt   uint32 // most recent round trip, microseconds
	stats pathStats
	mtu   mtuProbe
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

	mu       sync.Mutex
	paths    map[uint8]*pathState
	names    map[uint8]string
	lastEcho time.Duration
	lastSent time.Duration
}

func newSession(cfg *config.Holder, node, role string) *session {
	if cfg == nil {
		cfg = config.NewHolder(config.Defaults())
	}
	return &session{
		start: time.Now(),
		cfg:   cfg,
		node:  node,
		role:  role,
		paths: make(map[uint8]*pathState),
		names: make(map[uint8]string),
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
	}
	p.nextSeq++

	if now-s.lastEcho >= s.cfg.Get().EchoInterval() {
		h.Echo = s.collectEchoLocked(now)
		if len(h.Echo) > 0 {
			s.lastEcho = now
		}
	}
	s.lastSent = now
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

// dueForReport reports whether the reverse direction has been quiet long
// enough that feedback needs a packet of its own. Piggybacking on data is
// free, so it is always preferred; this only fires when there is no data
// to ride along with.
func (s *session) dueForReport() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.elapsed()-s.lastSent >= s.cfg.Get().EchoInterval()
}

// buildReport produces a standalone feedback packet for a path, carrying
// no payload of its own.
func (s *session) buildReport(pathID uint8, buf []byte) []byte {
	return s.build(protocol.TypeReport, pathID, s.nextGlobalSeq(), nil, buf)
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
			p.mtu.misses = 0
		}
		p.mtu.probing = 0
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

		if s.dueForReport() {
			for _, id := range pathIDs() {
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
		// A probe is confirmed when the peer reports having seen a packet
		// at least as large as the one sent, which answers the question
		// directly rather than inferring it from a timestamp.
		if ep.mtu.probing != 0 && int(e.MaxSeen) >= ep.mtu.probing-ipUDPOverhead {
			ep.mtu.confirmed = ep.mtu.probing
			ep.mtu.probing = 0
			ep.mtu.misses = 0
		}
	}
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
		if now := s.elapsed(); now-last < s.cfg.Get().StatsInterval() {
			continue
		} else {
			last = now
		}
		s.mu.Lock()
		for id, p := range s.paths {
			st := &p.stats
			log.Printf("path %d: rtt %.1fms p95-spread %.1fms jitter %.1fms queue %.1fms | "+
				"rx %d lost %d bursts %v | samples %d%s | mtu %d",
				id,
				ms(p.rtt), msi(st.spread()), st.jitter/1000, msi(st.queueDelay),
				st.received, st.lost, st.bursts,
				st.filled, thinNote(st.thin()),
				p.mtu.confirmed)
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
	return smallest - ipUDPOverhead - protocol.MaxHeaderLen - wireGuardOverhead
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

	s.mu.Lock()
	defer s.mu.Unlock()

	snap := state.Snapshot{
		Node:                 s.node,
		Role:                 s.role,
		UpdatedUnix:          float64(time.Now().UnixNano()) / 1e9,
		UptimeSeconds:        now.Seconds(),
		TunnelMTU:            tunnelMTU,
		RecommendedTunnelMTU: s.recommendedTunnelMTULocked(),
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
