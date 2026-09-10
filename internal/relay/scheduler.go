package relay

import (
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"sync/atomic"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
	"github.com/anthonysecco/OpenMultiPath/internal/diag"
	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
	"github.com/anthonysecco/OpenMultiPath/internal/usage"
)

// The scheduler decides which path or paths each packet goes out of.
//
// It replaces the unconditional duplication the daemon started with. That
// behaviour was deliberate scaffolding - scope-v1.md wanted the tunnel
// carrying traffic with full telemetry before any scheduling existed - but
// it has a specific cost that the field data has already shown: with every
// packet riding every path, any real load saturates the weakest link. On
// the current 512k Starlink standby plan that is not a subtlety, it is an
// 8000-packet collapse on a 10 MB copy.
//
// The decision is recomputed on a slow loop and published as an immutable
// value. The data path only ever reads that pointer, so steering a packet
// costs an atomic load and no lock, and a stall in evaluation degrades to
// "keeps using the last good decision" rather than to blocking the tunnel.

// pathView is the published per-path verdict, for the interface and the
// history log.
type pathView struct {
	State       string
	Reason      string
	Score       float64
	RFactor     float64
	MOS         float64
	Flapping    bool
	Transitions int
	Sending     bool
}

// decision is one complete scheduling verdict, published as a unit so that
// no reader can ever see a half-updated view.
type decision struct {
	// tx is the paths a real-time packet is sent on, in order, and txBulk
	// the paths a bulk one takes. Step 8: they are allowed to differ,
	// which is the entire point of having spent step 7 working out which
	// is which.
	//
	// Only real-time is ever duplicated. scope-v1.md is explicit that bulk
	// is sacrificial and that redundancy is for the call, and D-022 warned
	// that a policy which could not tell them apart would mirror a
	// download onto a 512k standby link because it looked healthy while
	// carrying nothing. It can tell them apart now.
	tx     []uint8
	txBulk []uint8

	// txBulkSpread is the set of paths a bulk flow may be load-balanced
	// across, one flow to one path by a hash of its 5-tuple (D-044). It is
	// the paths that are stable (D-044), big enough beside the best of them
	// (D-045), and actually delivering (D-046), minus the call's path while
	// a call is live - so healthy links aggregate for a multi-flow download
	// that would otherwise sit on one, while a link that would only drag the
	// others down is left out. Empty falls back to txBulk,
	// which keeps D-033's single-best choice for the forest-canopy case
	// where the only bulk-worthy link is an unstable one. Per flow, not per
	// packet: a single flow still rides a single path, so nothing reorders.
	txBulkSpread []uint8

	// txTrans is the transactional set: the primary alone.
	//
	// It follows real-time's path but never real-time's duplication.
	// Transactional wants the same link - shortest round trip, least loss
	// - and none of the redundancy, because a second copy of a web
	// request is unbounded cost for a flow TCP already recovers in one
	// RTT, and above WireGuard a duplicate is delivered twice rather than
	// dropped by a replay window.
	txTrans []uint8

	// withholdBulk is step 9. True means bulk is not being sent at all
	// this evaluation - dropped at the ingress rather than queued into a
	// link whose queue is already hurting the call. The zero value admits,
	// which is what emptyDecision needs: coming up withholding would
	// starve bulk until the first tick for no measured reason.
	withholdBulk bool

	primary     uint8
	havePrimary bool

	switching   bool
	switchingTo uint8

	// blind is set when no path is in a usable state and traffic is being
	// sprayed across everything that is bound, in the hope that one of
	// them works. It is the fail-to-a-working-state behaviour of principle
	// 5, and it is worth showing in the interface because it means the
	// measurements have stopped being able to say anything.
	blind bool

	reason string
	views  map[uint8]pathView

	// ranking is every eligible path, best first. architecture.md's
	// fallback design needs this: the scheduler is the thing that will
	// have died, so it has to leave its opinion written down where a
	// script can find it.
	ranking []int
}

// scored pairs a path's measurements with its machine and the number the
// scheduler ranks on.
type scored struct {
	m     pathMetric
	mach  *machine
	score float64

	// delayMs is kept alongside the score purely to break ties. Two paths
	// that are both comfortably below the delay knee both score the
	// maximum, because the model is measuring impairment and neither is
	// impaired - which is correct, and useless for choosing between them.
	// Falling back on map order there would have picked by path id, and
	// path 0 is the metered satellite link.
	delayMs float64
}

// emptyDecision is what the data path reads before the first evaluation.
// Sending nothing would be the wrong default - the tunnel would be dead
// until the first tick - so the caller falls back to every bound path.
var emptyDecision = &decision{views: map[uint8]pathView{}}

type scheduler struct {
	sess *session
	cfg  *config.Holder

	// candidates reports the paths that can actually be transmitted on
	// right now. For the initiator that is the bound sockets; for the
	// responder it is the paths the far end has made contact on.
	candidates func() []uint8

	// source supplies the measurements to evaluate. It is the session in
	// every real build; having it as a field is what lets the scheduling
	// rules be tested against synthetic paths, which matters more than
	// usual here because the conditions worth testing - a canyon, an hour
	// under forest canopy - cannot be produced on a bench.
	source func(time.Duration) []pathMetric

	cur atomic.Pointer[decision]

	// Everything below is owned by the evaluation goroutine alone and
	// needs no synchronisation.
	machines map[uint8]*machine

	primary     uint8
	havePrimary bool

	// challenger is a path that has been scoring better than the primary,
	// and challengerFor how many consecutive evaluations it has managed
	// it. Stickiness is mandatory: without this an established flow
	// oscillates every time two scores cross.
	challenger    uint8
	challengerFor int

	// withholdingBulk is the admission gate, and bulkClearFor how many
	// consecutive evaluations have seen the queue back under the line. The
	// gate is deliberately asymmetric - see AdmissionRecoverIntervals.
	withholdingBulk bool
	bulkClearFor    int

	// bulkPath is the path bulk was steered onto, held across evaluations
	// so a flow is not walked between links every time two scores cross.
	// Unset means bulk is riding the primary because nothing else was
	// free.
	bulkPath     uint8
	haveBulkPath bool

	// labels is each path's human name, refreshed from the metrics every
	// evaluation so the log sites that only hold an id can still name a
	// link the way the operator does. A map rather than a lookup back into
	// config because the evaluation goroutine owns this and config is
	// behind a holder.
	labels map[uint8]string

	// classifying mirrors whether the classifier is actually running.
	// Below WireGuard it is not: payloads are ciphertext, every packet
	// comes back ClassUnknown, and a gate that treats unknown as bulk
	// would withhold the call along with the download - killing the
	// tunnel at exactly the moment the link is congested, which is the
	// precise opposite of the point. Starving bulk is only meaningful
	// where bulk can be told from a call.
	classifying atomic.Bool

	switching      bool
	switchFrom     uint8
	switchingTo    uint8
	switchingSince time.Duration

	// pin is an operator-requested override (D-048): force one flow onto
	// one path, bypassing D-044's hash and every gate above it. Set by
	// watchDiagPin from a file ompui writes, read by txFor on the data
	// path, so it needs its own synchronisation rather than living with
	// the fields above that the evaluation goroutine owns alone.
	pin atomic.Pointer[diagPin]

	// nowFn is where txFor gets wall-clock time to check the pin's
	// deadline. A field rather than a bare time.Now() so a test can hold
	// it still; every other clock read in this file goes through the
	// session's synthetic elapsed time, but the pin's deadline comes from
	// ompui as a wall-clock Unix timestamp, since ompui has no way to know
	// the daemon's synthetic clock.
	nowFn func() time.Time
}

// diagPin is a matched, resolved pin: the exact hash the target flow's
// packets will produce, the path to force them onto, and the deadline
// after which the pin stops applying even if nothing ever clears the file.
// The deadline is the backstop - see diag.PinRequest - for ompui crashing
// or being killed mid-test, so a stuck pin cannot silently outlive it.
type diagPin struct {
	flow    uint32
	path    uint8
	expires time.Time
}

func newScheduler(sess *session, cfg *config.Holder, candidates func() []uint8) *scheduler {
	s := &scheduler{
		sess:       sess,
		cfg:        cfg,
		candidates: candidates,
		source:     sess.metrics,
		machines:   make(map[uint8]*machine),
		nowFn:      time.Now,
	}
	s.cur.Store(emptyDecision)
	return s
}

// setClassifying tells the scheduler whether classes are real. See the
// field comment: admission control is disabled outright when they are not.
func (s *scheduler) setClassifying(on bool) { s.classifying.Store(on) }

// current is the decision in force. Never nil.
func (s *scheduler) current() *decision { return s.cur.Load() }

// txPaths is the data path's entire interface to the scheduler: the paths
// this packet should go out of.
// txPaths is the set of paths one packet of the given class goes out of.
//
// Real-time and transactional take the same path, and only bulk is sent
// somewhere else.
//
// That is the simplification the third class buys. Both of the first two
// want the same thing from a link - the shortest round trip and the least
// loss - and differ only in what happens when it is not available. Bulk
// is the one class that wants a fat pipe instead and does not care about
// round trips, so the placement question is not three-way: it is "keep
// the transfer away from everything else".
//
// Anything the classifier could not place rides with them. With three
// classes the middle is the safe default (see internal/classify), and the
// cost of being wrong is bounded either way: an unplaced flow is never
// duplicated, and it moves off within a dwell if it turns out to be a
// transfer.
func (s *scheduler) txPaths(class uint8) []uint8 {
	d := s.cur.Load()
	switch class {
	case protocol.ClassBulk:
		return d.txBulk
	case protocol.ClassRealtime:
		return d.tx
	default:
		// Transactional, and anything still unplaced, which the
		// classifier treats as transactional too.
		if len(d.txTrans) == 0 {
			return d.tx
		}
		return d.txTrans
	}
}

// txFor is txPaths for a specific flow: it is what the data path calls, and it
// differs from txPaths only for bulk, where a flow is hashed onto one of the
// load-balancing paths (D-044) so several flows fill several links without any
// single flow being split across paths. Real-time and transactional are
// identical to txPaths - real-time still duplicates across its whole set, and
// transactional still rides the primary alone.
func (s *scheduler) txFor(class uint8, flow uint32) []uint8 {
	// Real-time is duplicated across its whole set, never hashed onto one
	// path - redundancy is the point, and it is the one class that must not
	// be load-balanced.
	if class == protocol.ClassRealtime {
		return s.txPaths(class)
	}

	// D-048's operator override, checked before any gate below: the whole
	// point is to answer what a specific link does under load, including a
	// link the gates currently exclude, which requires routing around them
	// rather than through them. Scoped to exactly the one flow ompui named
	// and expiring on its own even if the file that set it is never
	// cleared - see diagPin.
	if p := s.pin.Load(); p != nil && p.flow == flow {
		if s.nowFn().Before(p.expires) {
			return []uint8{p.path}
		}
		s.pin.Store(nil)
	}
	// Bulk and transactional both load-balance per flow across the healthy
	// set. Transactional joins bulk here because pinning it to the primary
	// leaves a second link idle for exactly the multi-connection traffic -
	// a page's many requests, or a download the classifier has not yet
	// called an elephant - that a second link would speed up; each flow
	// still rides one stable path, so a request's ordering is untouched.
	d := s.cur.Load()
	if n := len(d.txBulkSpread); n > 0 {
		i := flow % uint32(n)
		return d.txBulkSpread[i : i+1]
	}
	// Nothing to spread across (a call holds the only healthy paths, or one
	// is left): fall back to the class's default - bulk to its steered path,
	// transactional to the primary.
	if class == protocol.ClassBulk {
		return d.txBulk
	}
	if len(d.txTrans) == 0 {
		return d.tx
	}
	return d.txTrans
}

// deliveringForSpread reports whether a path is actually getting bytes to the
// far end well enough to be handed flows (D-046).
//
// D-044 admitted the stable paths and D-045 added size. Both missed the link
// that was actually hurting: one dropping 66-71% of what it was given, which
// the state machine still called "stable (clean)" because its loss counter was
// windowed and its jitter and queue delay were fine. Loss without queueing is
// invisible to every delay-derived signal - the packet does not wait, it
// vanishes - so neither stability nor the bandwidth ceiling could see it. The
// measurement that could was already being taken and simply was not consulted.
//
// Two conditions, because they fail differently:
//
//   - Quality now. The R factor over the send direction the peer reports
//     (D-024), so it describes what our traffic is experiencing rather than
//     what is arriving here. Raw rFactor rather than machine.score: score
//     folds in the metered-link surcharge, and being expensive is not the same
//     as being broken. Cost is already handled by the Red test above.
//
//   - Reliability over time. A flapping path can read fine at the instant it
//     is sampled and still be unusable, which is exactly how the D-046 link
//     kept rejoining the set - it oscillated across the stability threshold
//     and got its half of the flows back every time it landed on the good
//     side. machine.flapping is the existing answer to that, and its own
//     documentation ("the correct behaviour is to stop trying") is precisely
//     this case.
//
// Excluding a path here does not make it ineligible. Bulk still falls back to
// the single steered path of D-033, which is deliberately unguarded - a
// flapping link is a fine place for traffic that can wait, when the
// alternative is putting it on the call's path. This gate governs only which
// paths are worth *spreading across*.
func deliveringForSpread(now time.Duration, sc scored, c config.Config) bool {
	if rFactor(scoreInputs(sc.m, c)) < float64(c.SpreadMinR) {
		return false
	}
	return !sc.mach.flapping(now, c)
}

// pathName is how the scheduler names a path in a log line. It is the link's
// configured label where there is one, and the bare id where there is not -
// which is what every message said before labels existed.
func (s *scheduler) pathName(id uint8) string {
	if s.labels == nil {
		return fmt.Sprintf("path %d", id)
	}
	return pathLabel(id, s.labels[id])
}

// undersizedForSpread reports whether a path is too small a share of the best
// candidate to be worth hashing bulk flows onto (D-045).
//
// The load-balancing set is a set of peers. txFor spreads flows across it with
// a uniform hash, so every member takes its share of the flows no matter what
// it can carry, and a flow that lands on a member stays there for its whole
// life. Between links of comparable size that is exactly right. Between links
// an order of magnitude apart it means half the transfers on the box run at
// the speed of the worst link - which on this project is the normal case, not
// a corner: a 636 kbps cellular link beside a 30 Mbps one is what D-045 was
// written from.
//
// D-044's stability filter cannot catch this. The small link is not unstable;
// it is not losing packets and its jitter is fine. It is simply small, and
// stability has no term for size.
//
// Unknown is permission, as everywhere a limit is read (D-023): a path with no
// measured ceiling is never excluded, because never having watched a link fill
// up is not evidence that it is small. A zero best means no candidate has an
// opinion and the gate is off entirely. Between them these two cases are also
// what keeps the gate from ever emptying a non-empty spread - the best
// candidate is 100% of itself, and the share bound tops out at 100.
func undersizedForSpread(limitKbps, bestKbps float64, c config.Config) bool {
	if limitKbps <= 0 || bestKbps <= 0 {
		return false
	}
	return limitKbps*100 < bestKbps*float64(c.BulkSpreadMinSharePercent)
}

// flowHash is a stable hash of an inner IPv4 packet's 5-tuple, used to pin a
// bulk flow to one load-balancing path. Same flow, same path, every packet -
// which is what keeps load balancing from turning into reordering. FNV-1a over
// the addresses, protocol, and (for TCP/UDP) ports; a packet too short or not
// IPv4 hashes to zero, which simply lands it on the first path.
func flowHash(p []byte) uint32 {
	if len(p) < 20 || p[0]>>4 != 4 {
		return 0
	}
	const (
		offset = 2166136261
		prime  = 16777619
	)
	h := uint32(offset)
	for _, b := range p[12:20] { // source and destination address
		h = (h ^ uint32(b)) * prime
	}
	h = (h ^ uint32(p[9])) * prime // protocol
	if ihl := int(p[0]&0x0f) * 4; (p[9] == 6 || p[9] == 17) && len(p) >= ihl+4 {
		for _, b := range p[ihl : ihl+4] { // source and destination port
			h = (h ^ uint32(b)) * prime
		}
	}
	return h
}

// flowHashTuple computes exactly what flowHash would compute for a packet
// with this 5-tuple, without needing a real packet to hash. Used only to
// resolve a diag.PinRequest (D-048): ompui knows the 5-tuple its own probe
// traffic will carry before it sends a single packet, and this lets it ask
// the daemon to recognise that flow by the same hash the data path already
// computes, rather than adding a second way to identify a flow.
//
// Kept byte-for-byte identical to flowHash on purpose - see
// TestFlowHashTupleMatchesFlowHash - so the two can never quietly drift
// apart.
func flowHashTuple(src, dst net.IP, proto uint8, srcPort, dstPort uint16) uint32 {
	const (
		offset = 2166136261
		prime  = 16777619
	)
	s4, d4 := src.To4(), dst.To4()
	if s4 == nil || d4 == nil {
		return 0
	}
	h := uint32(offset)
	for _, b := range s4 {
		h = (h ^ uint32(b)) * prime
	}
	for _, b := range d4 {
		h = (h ^ uint32(b)) * prime
	}
	h = (h ^ uint32(proto)) * prime
	if proto == 6 || proto == 17 {
		for _, b := range [4]byte{byte(srcPort >> 8), byte(srcPort), byte(dstPort >> 8), byte(dstPort)} {
			h = (h ^ uint32(b)) * prime
		}
	}
	return h
}

// watchDiagPin polls path for an operator-requested pin (D-048), the same
// way config.Holder.Watch polls settings - mtime and size, not "newer", for
// the reasons given there: a restored backup or a clock stepped backwards
// must not hide a real change.
//
// Nothing calls this on the responder. Only the initiator chooses among
// more than one physical path, so only it has a hash for an override to
// replace.
func (s *scheduler) watchDiagPin(path string) {
	var last time.Time
	var lastSize int64
	var seen bool
	for range time.Tick(500 * time.Millisecond) {
		fi, err := os.Stat(path)
		if err != nil {
			if seen {
				s.pin.Store(nil)
				seen = false
			}
			continue
		}
		if seen && fi.ModTime().Equal(last) && fi.Size() == lastSize {
			continue
		}
		last, lastSize, seen = fi.ModTime(), fi.Size(), true

		req, err := diag.ReadPin(path)
		if err != nil {
			log.Printf("diag pin: %v, ignoring", err)
			continue
		}
		flow := flowHashTuple(net.ParseIP(req.SrcIP), net.ParseIP(req.DstIP), req.Protocol, req.SrcPort, req.DstPort)
		expires := time.Unix(req.ExpiresUnix, 0)
		s.pin.Store(&diagPin{flow: flow, path: req.PathID, expires: expires})
		log.Printf("diag pin: forcing flow %d onto %s until %s", flow, s.pathName(req.PathID), expires.Format(time.RFC3339))
	}
}

// admit reports whether a packet of this class should be sent at all.
//
// This is the one place the daemon deliberately destroys traffic, and
// protocol.md is blunt about why. With a call and a download sharing a
// path whose queue is filling, the download is what is adding hundreds of
// milliseconds to the call: dropping it costs a stalled page, and carrying
// it costs the meeting. Dropped here at the ingress the sending stack
// backs off on its own, so the queue that forms is in a client on the LAN
// where it is free rather than in the WAN uplink where it is not.
//
// Real-time is never withheld. That is the absolute reservation
// scope-v1.md asks for, and it is also why a gate is enough where a shaper
// would otherwise be needed: the class that must not be starved is exactly
// the one too small to need pacing.
func (s *scheduler) admit(class uint8) bool {
	if class == protocol.ClassRealtime {
		return true
	}

	// Transactional is never gated, and this is the correction the class
	// was really for.
	//
	// The gate is right for a download: dropping it costs a stall, TCP
	// backs off, and the queue re-forms in a LAN client where it is free.
	// It is wrong for a web request, which is small enough to cost the
	// call nothing and short enough that a drop means seconds of dead air
	// and a retry. Withholding it was the daemon destroying the traffic
	// the user is watching in order to protect the traffic they are
	// listening to.
	//
	// Priority rather than a reservation, deliberately. Once bulk is
	// withheld the uplink drains, and transactional is small enough to
	// fit in what is left - so the cheap answer is simply not to gate it.
	// A real reservation means a shaper, and a shaper means sizing a
	// bucket from numbers nobody has measured yet. That is v2's job, with
	// the field data D-031 and this both lack.
	if class == protocol.ClassTransactional {
		return true
	}

	if !s.classifying.Load() {
		return true
	}
	return !s.cur.Load().withholdBulk
}

// steerBulk puts bulk on the best path real-time is not using, which is
// the rest of step 8 and the thing that makes step 9 rare.
//
// The rule is one sentence: bulk takes the best eligible path that
// real-time is not on, and shares the primary only when real-time is using
// all of them. The whole cost of bulk sharing the call's path is a
// standing queue built by a download, arriving as delay in a meeting. The
// whole cost of moving it is a slower page, and scope-v1.md calls web and
// map traffic explicitly sacrificial. That ordering is not close.
//
// It is also, in one rule, two scenarios the walkthrough asks for
// separately. "Pull bulk off Starlink immediately" on a canyon approach
// happens because the degrading link stops being the primary. "Use
// Starlink only for bulk, where intermittency costs nothing" under forest
// canopy happens because an unstable path is still eligible - which is why
// no capacity or stability test guards the target. A flapping link is a
// perfectly good place to put traffic that can wait, and refusing to use
// it would leave the download on the call's path instead, which is the
// outcome this exists to prevent.
//
// Nothing here is cost-aware yet. It does not need to be: the target is
// taken from the eligible ranking, so once step 10 puts a billing penalty
// into the score, bulk stops being steered onto an expensive link without
// this code changing.
func (s *scheduler) steerBulk(now time.Duration, d *decision, c config.Config, eligible []scored) {
	// Blind mode has no opinion worth acting on - see buildTx, which
	// sprays both classes alike because the measurements have stopped
	// being able to tell them apart.
	if d.blind || !d.havePrimary {
		s.setBulkPath(0, false)
		return
	}

	// The same trap step 9 fell into, and worth stating separately
	// because it bites harder here. Below WireGuard payloads are
	// ciphertext, nothing can be classified, and every packet comes back
	// ClassUnknown - which D-027 carries as bulk. Steering on that would
	// not merely mislabel traffic, it would move *all* of it off the best
	// path onto the second best, leaving the primary carrying probes and
	// the call riding whatever was left over. Keeping the call off the
	// download's path is only meaningful where the two can be told apart.
	if !s.classifying.Load() {
		s.setBulkPath(0, false)
		return
	}

	carrying := make(map[uint8]bool, len(d.tx))
	for _, id := range d.tx {
		carrying[id] = true
	}

	// The load-balancing set (D-044): stable, non-red, big enough, delivering.
	// Bulk flows are hashed across these so a multi-flow download uses every
	// healthy link rather than one. Stable-only on purpose: an unstable link
	// (cellular loss spiking) stays out, so it cannot drag the aggregate
	// below a single good path - the exact failure that made a two-link
	// download slower than one. eligible is already sorted best-first.
	//
	// Stability alone turned out not to be enough (D-045). A link can be
	// perfectly stable - no current loss, low jitter, and so correctly
	// called clean - and still be fifty times smaller than the path beside
	// it. The hash does not care: it hands that link its half of the flows
	// anyway, and each one sits there at a fraction of the rate for its
	// whole life. So size is now a membership test too, and the failure the
	// paragraph above describes stops arriving through the other door.
	//
	// Nor was size enough (D-046). The link that was actually hurting was
	// neither unstable nor small: it was dropping two thirds of what it was
	// given, which no delay-derived signal can see - a dropped packet does
	// not queue - and which the state machine missed because it reads the
	// receive direction while the damage was in the send direction. See
	// deliveringForSpread.
	//
	// The call's path is reserved only while a call is actually flowing.
	// D-033 keeps bulk off the primary to protect real-time, but with no
	// call live there is nothing to protect and reserving it would strand a
	// whole uplink - so an idle-of-calls tunnel lets bulk have every link,
	// and a call starting pulls bulk back off its path within the window.
	rtActive := s.sess != nil && s.sess.realtimeActive(now)
	spreadable := func(sc scored) bool {
		if sc.m.budget.Band == usage.Red || sc.mach.state != stateStable {
			return false
		}
		if !deliveringForSpread(now, sc, c) {
			return false
		}
		return !(rtActive && carrying[sc.m.id])
	}

	// The best measured ceiling among the candidates, which is the bar the
	// others have to be worth a fraction of (D-045). Taken over the
	// candidates and not over eligible: a path real-time is holding is not
	// in the running for bulk, so its capacity must not set a bar that
	// knocks out the links that are.
	var bestKbps float64
	for _, sc := range eligible {
		if spreadable(sc) && sc.m.bw.limitKbps > bestKbps {
			bestKbps = sc.m.bw.limitKbps
		}
	}

	d.txBulkSpread = d.txBulkSpread[:0]
	for _, sc := range eligible {
		if !spreadable(sc) || undersizedForSpread(sc.m.bw.limitKbps, bestKbps, c) {
			continue
		}
		d.txBulkSpread = append(d.txBulkSpread, sc.m.id)
	}
	// Order by path id, not by score. The hash maps a flow to an index in
	// this slice, so the order has to be stable: two links of nearly equal
	// score swap best-first order from one evaluation to the next, and if
	// the slice reordered under it a flow's index would point at a different
	// path each tick - bouncing the flow between links, which is reordering
	// by another name and collapses the very TCP flow it was meant to speed
	// up. Sorting by id pins a flow to one path as long as the membership
	// holds, and membership changes only on a state transition, rarely.
	sort.Slice(d.txBulkSpread, func(i, j int) bool { return d.txBulkSpread[i] < d.txBulkSpread[j] })

	// Pick the cheapest band first and the ranking second. Bulk is the
	// second thing a budget sacrifices, after duplication and well before
	// the call, so where it can spend matters more than how fast.
	//
	// A red link is skipped outright: the allowance is gone, and
	// architecture.md reserves what is left of it for a call. Yellow is
	// not - being on course to exceed a cap is not the same as having
	// spent it, and stalling every download over a projection would be
	// acting on an estimate as though it were a fact.
	best, haveBest := uint8(0), false
	var bestBand usage.Band
	for _, sc := range eligible {
		if carrying[sc.m.id] || sc.m.budget.Band == usage.Red {
			continue
		}
		// eligible is sorted best-first, so the first path at a given
		// band is also the best-scoring one at that band.
		if !haveBest || sc.m.budget.Band < bestBand {
			best, bestBand, haveBest = sc.m.id, sc.m.budget.Band, true
		}
	}

	// Stickiness, against scores but not against bands. Moving bulk
	// between links reorders every TCP flow in progress on it, and the
	// receiver reads reordering as loss and retransmits - so chasing the
	// better link each time two scores crossed would pay for the move
	// over and over in exactly the traffic it was meant to speed up.
	//
	// A band is different in kind. Scores cross many times an hour; a
	// band changes a handful of times a month and means real money. So
	// bulk holds its path against a better score and gives it up for a
	// better band, and a link that turns red loses it immediately.
	if s.haveBulkPath && !carrying[s.bulkPath] {
		if m, ok := s.metricOf(s.bulkPath, eligible); ok &&
			m.budget.Band != usage.Red &&
			(!haveBest || m.budget.Band <= bestBand) {
			d.txBulk = []uint8{s.bulkPath}
			return
		}
	}

	if haveBest {
		s.setBulkPath(best, true)
		d.txBulk = []uint8{best}
		return
	}

	// Real-time is on everything usable, or everything else is red. Bulk
	// shares the primary, as buildTx left it, and admission control
	// decides whether it flows.
	s.setBulkPath(0, false)
}

// setBulkPath records where bulk is going, logging only the transitions.
// The scheduler evaluates five times a second and the journal lives on the
// box that is hardest to reach.
func (s *scheduler) setBulkPath(id uint8, have bool) {
	if s.haveBulkPath == have && (!have || s.bulkPath == id) {
		return
	}
	s.bulkPath, s.haveBulkPath = id, have
	if have {
		log.Printf("scheduler: bulk -> %s, off the call's path", s.pathName(id))
	} else {
		log.Printf("scheduler: bulk -> %s, sharing the call's path (nothing else usable)", s.pathName(s.primary))
	}
}

// applyAdmission sets the gate for this evaluation.
func (s *scheduler) applyAdmission(d *decision, c config.Config, eligible []scored) {
	q, ok := sharedQueueMs(d, eligible)
	if !s.classifying.Load() {
		// Reported as open, not merely ignored: the interface should not
		// claim to be starving bulk that it cannot identify.
		s.setWithholding(false)
		d.withholdBulk = false
		return
	}
	if !ok {
		// Either nothing is shared, or there is no evidence about our own
		// send direction. Neither justifies starving anything.
		s.setWithholding(false)
		d.withholdBulk = false
		return
	}

	switch {
	case q > float64(c.AdmissionQueueDelayMs):
		// Shut on the first evaluation over the line. The call is being
		// damaged while this is being measured; waiting to confirm would
		// be confirming it with the meeting.
		s.bulkClearFor = 0
		s.setWithholding(true)
	case s.withholdingBulk:
		s.bulkClearFor++
		if s.bulkClearFor >= c.AdmissionRecoverIntervals {
			s.setWithholding(false)
		}
	}

	d.withholdBulk = s.withholdingBulk
	if s.withholdingBulk {
		d.reason = fmt.Sprintf("bulk withheld, %.0f ms queue on the call's path", q)
	}
}

// setWithholding flips the gate, logging only the transition. The gate is
// checked on every packet and evaluated five times a second; logging the
// state rather than the change would bury the journal on the box that is
// hardest to reach.
func (s *scheduler) setWithholding(on bool) {
	if s.withholdingBulk == on {
		return
	}
	s.withholdingBulk = on
	if on {
		log.Printf("admission: withholding bulk, the call's path is queueing")
	} else {
		s.bulkClearFor = 0
		log.Printf("admission: admitting bulk again")
	}
}

// sharedQueueMs is the send-direction queue delay on the path carrying
// both classes, when there is one.
//
// Two conditions have to hold before starving bulk is the right answer.
// The classes must actually share a path - once bulk can be steered onto
// one of its own its queue is nobody else's problem - and the far end must
// have reported our send direction, because that is the only direction our
// own bulk fills. Acting on the receive figure would starve a download for
// a downlink it is not responsible for. See D-024.
func sharedQueueMs(d *decision, eligible []scored) (float64, bool) {
	if d.blind {
		return 0, false
	}
	for _, b := range d.txBulk {
		for _, r := range d.tx {
			if b != r {
				continue
			}
			for _, sc := range eligible {
				if sc.m.id == b && sc.m.haveTx {
					return sc.m.txQueueMs, true
				}
			}
		}
	}
	return 0, false
}

// run evaluates forever on the configured cadence.
//
// A fixed fast tick with the interval checked against the clock, matching
// the other loops: the cadence is adjustable while running and this way a
// change takes effect on the next tick rather than needing the ticker
// rebuilt.
func (s *scheduler) run() {
	const tick = 20 * time.Millisecond
	var last time.Duration

	for range time.Tick(tick) {
		c := s.cfg.Get()
		now := s.sess.elapsed()
		if now-last < c.EvalInterval() {
			continue
		}
		last = now
		s.evaluate(now, c)
	}
}

// evaluate advances every path's machine, picks a primary, and publishes
// the result.
func (s *scheduler) evaluate(now time.Duration, c config.Config) {
	sendable := make(map[uint8]bool)
	for _, id := range s.candidates() {
		sendable[id] = true
	}

	metrics := s.source(now)
	sort.Slice(metrics, func(i, j int) bool { return metrics[i].id < metrics[j].id })

	// Refresh the names before anything can log. A path that appeared this
	// tick must not be announced as a bare id and then renamed next tick.
	if s.labels == nil {
		s.labels = make(map[uint8]string, len(metrics))
	}
	for _, p := range metrics {
		s.labels[p.id] = p.label
	}

	// Advance the machines and score what came out.
	all := make([]scored, 0, len(metrics))
	for _, p := range metrics {
		mach := s.machines[p.id]
		if mach == nil {
			// A path starts down and has to earn its way up. Starting
			// anywhere else would have the scheduler trusting a path it
			// has never measured, which is exactly what the promotion
			// rules exist to prevent.
			mach = &machine{reason: "not yet measured"}
			s.machines[p.id] = mach
		}
		prev := mach.state
		if mach.evaluate(now, p, c) {
			// A path coming up from down is the one moment its MTU can
			// have changed unseen - a reconnect onto a different bearer -
			// so restart its MTU search here rather than re-probing every
			// path on a timer forever (D-039).
			if s.sess != nil && prev == stateDown && mach.state != stateDown {
				s.sess.rearmMTU(p.id)
			}
			log.Printf("%s: %s (%s)", s.pathName(p.id), mach.state, mach.reason)
		}
		all = append(all, scored{
			m:       p,
			mach:    mach,
			score:   mach.score(now, p, c),
			delayMs: scoringDelayMs(p, c),
		})
	}

	// Eligible means both usable in principle and reachable in practice.
	eligible := make([]scored, 0, len(all))
	for _, sc := range all {
		if sc.mach.state != stateDown && sendable[sc.m.id] {
			eligible = append(eligible, sc)
		}
	}
	sort.SliceStable(eligible, func(i, j int) bool {
		if eligible[i].score != eligible[j].score {
			return eligible[i].score > eligible[j].score
		}
		return eligible[i].delayMs < eligible[j].delayMs
	})

	d := &decision{views: make(map[uint8]pathView, len(all))}
	for _, sc := range eligible {
		d.ranking = append(d.ranking, int(sc.m.id))
	}

	s.choose(now, c, eligible)
	s.buildTx(d, c, eligible, sendable)
	s.steerBulk(now, d, c, eligible)
	s.applyAdmission(d, c, eligible)

	for _, sc := range all {
		d.views[sc.m.id] = pathView{
			State:       sc.mach.state.String(),
			Reason:      sc.mach.reason,
			Score:       sc.score,
			RFactor:     rFactor(scoreInputs(sc.m, c)),
			MOS:         mosFrom(sc.score),
			Flapping:    sc.mach.flapping(now, c),
			Transitions: len(sc.mach.transitions),
		}
	}
	for _, id := range d.tx {
		v := d.views[id]
		v.Sending = true
		d.views[id] = v
	}

	s.cur.Store(d)
}

// choose settles the primary path, applying stickiness and running any
// make-before-break handover that is in flight.
func (s *scheduler) choose(now time.Duration, c config.Config, eligible []scored) {
	if len(eligible) == 0 {
		// Nothing is usable. Hold the primary rather than forgetting it:
		// when a link comes back it is usually the same one, and keeping
		// the choice avoids a pointless handover on recovery.
		s.switching = false
		return
	}

	best := eligible[0]

	// A handover already in flight is seen through rather than
	// relitigated. Re-deciding every tick during an overlap is how a
	// scheduler ends up oscillating between two paths it is already
	// sending on.
	if s.switching {
		s.advanceSwitch(now, c, eligible)
		return
	}

	cur, ok := s.scoreOf(s.primary, eligible)
	if !s.havePrimary || !ok {
		s.adopt(best.m.id, "no usable primary")
		return
	}
	if best.m.id == s.primary {
		// The primary is still top-ranked, so there is nothing to decide.
		//
		// This used to reach for capacity as a tie-break (D-023's roomier),
		// because tied scores are unbreakable - a challenger must beat the
		// incumbent by SwitchMarginR and a tie never will - and on
		// 2026-09-01 that pinned a flow to a 512 kbps standby link with a
		// multi-megabit one idle beside it. D-047 removed it. The complaint
		// in that field case was throughput, and throughput no longer
		// follows the primary: D-044 spreads bulk and transactional per
		// flow across every delivering link regardless of which one is
		// carrying the call, so the idle link gets the transfer without the
		// call having to move at all. What was left was moving the *call*
		// on the least reliable number in the system, for a benefit that
		// had already been collected elsewhere.
		s.challengerFor = 0
		return
	}

	// The absolute floor. protocol.md is firm that a real-time flow should
	// move because its current path has become inadequate, not because
	// something else looks marginally nicer - so a challenger with a
	// better score is not on its own a reason to move.
	if cur < float64(c.MinAcceptableR) && best.score > cur {
		// Where several paths could take the flow, prefer the one with the
		// most room rather than whichever scored a fraction higher. Scores
		// bunch at the top of the scale - every healthy path reads 93.2,
		// because the E-model measures impairment and an unimpaired path
		// has none - so the ranking here is often decided by a couple of
		// milliseconds that no call can perceive, while the capacity
		// difference between the candidates can be two orders of magnitude.
		s.beginSwitch(now, s.escapeTo(cur, eligible), "current path below the floor")
		return
	}

	if best.score > cur+float64(c.SwitchMarginR) {
		// A better-scoring path that cannot carry what the current one is
		// carrying is not a better path, it is a smaller one that has not
		// been asked to prove it yet. Moving onto it would trade a working
		// transfer for a nicer set of numbers.
		//
		// Only the opportunistic branch is gated. Below the floor, above,
		// the current path is failing and the load it is "carrying" is
		// theoretical - there, a small path that works beats a large one
		// that does not.
		if !s.canTake(best, s.offeredKbps(eligible), c) {
			s.challengerFor = 0
			return
		}
		if s.challenger == best.m.id {
			s.challengerFor++
		} else {
			s.challenger, s.challengerFor = best.m.id, 1
		}
		if s.challengerFor >= c.SwitchHoldIntervals {
			s.beginSwitch(now, best.m.id, "sustained better path")
		}
		return
	}

	// Nothing is materially better on quality, so the call stays where it
	// is. Ties are still unbreakable here - a challenger must beat the
	// incumbent by SwitchMarginR and equal scores never will - and that is
	// now deliberate. Capacity used to break the tie (D-023's roomier);
	// D-047 removed it, because the field case it was built for was a
	// throughput complaint and D-044 already answers that without moving
	// the call. Leaving a healthy call alone is the conservative reading of
	// principle 4, and it is the reading this scheduler should have.
	s.challengerFor = 0
}

// escapeTo picks where a failing path should hand off to: the best-scoring
// candidate that can actually carry the load, falling back to the
// best-scoring one outright when none can.
//
// The fallback is the point. Principle 5 - a small path that works beats a
// large one that does not, and a link-starved RV must still be able to move
// onto its only remaining option however capacity-poor it is.
func (s *scheduler) escapeTo(cur float64, eligible []scored) uint8 {
	load := s.offeredKbps(eligible)
	c := s.cfg.Get()
	for _, sc := range eligible {
		if sc.m.id == s.primary || sc.score <= cur {
			continue
		}
		if s.canTake(sc, load, c) {
			return sc.m.id
		}
	}
	return eligible[0].m.id
}

// offeredKbps is how much the primary is currently being asked to carry,
// which is what any path taking over from it has to be able to take.
func (s *scheduler) offeredKbps(eligible []scored) float64 {
	if !s.havePrimary {
		return 0
	}
	if m, ok := s.metricOf(s.primary, eligible); ok {
		return m.bw.sendKbps
	}
	return 0
}

// canTake reports whether a path may be offered this much on top of what it
// is already doing. A path with no capacity estimate always may - the gate
// refuses on evidence, never on ignorance.
func (s *scheduler) canTake(sc scored, loadKbps float64, c config.Config) bool {
	// Duplication is the first thing sacrificed to a budget, and by some
	// distance the easiest: a second copy is by definition redundant, so
	// cutting it costs resilience but not function. architecture.md puts
	// it ahead of bulk and well ahead of real-time for exactly that
	// reason, and a duplicate is the one traffic here that doubles a
	// link's spend to buy insurance nobody has yet needed.
	if sc.m.budget.Band != usage.Green {
		return false
	}
	return sc.m.bw.canCarry(loadKbps, c)
}

// adopt takes a path as primary with no overlap. Used only when there is no
// working path to overlap with, since there is nothing to make before
// breaking.
func (s *scheduler) adopt(id uint8, why string) {
	if s.havePrimary && s.primary == id {
		return
	}
	log.Printf("scheduler: primary -> %s (%s)", s.pathName(id), why)
	s.primary, s.havePrimary = id, true
	s.switching, s.challengerFor = false, 0
}

// beginSwitch starts a make-before-break handover: both paths carry the
// traffic until the new one is confirmed. Never cut then connect - a gap is
// audible.
func (s *scheduler) beginSwitch(now time.Duration, to uint8, why string) {
	log.Printf("scheduler: handover %s -> %s (%s), overlapping", s.pathName(s.primary), s.pathName(to), why)
	s.switching = true
	s.switchFrom = s.primary
	s.switchingTo = to
	s.switchingSince = now
	s.challengerFor = 0
}

// advanceSwitch decides whether an in-flight handover is finished.
func (s *scheduler) advanceSwitch(now time.Duration, c config.Config, eligible []scored) {
	elapsed := now - s.switchingSince

	// If the target died mid-handover, abandon it and stay put. The old
	// path is still carrying traffic, which is the entire reason for
	// overlapping in the first place.
	target, ok := s.metricOf(s.switchingTo, eligible)
	if !ok {
		log.Printf("scheduler: handover to %s abandoned, it is no longer usable", s.pathName(s.switchingTo))
		s.switching = false
		return
	}

	// Confirmation means the peer echoed something we sent on the new
	// path after the handover began. Receiving on a path proves only the
	// reverse direction, and a path can be fine inbound and dead outbound.
	confirmed := target.confirmedAt > s.switchingSince

	switch {
	case confirmed && elapsed >= c.MBBMin():
		log.Printf("scheduler: handover to %s confirmed after %v", s.pathName(s.switchingTo), elapsed.Round(time.Millisecond))
	case elapsed >= c.MBBMax():
		// Unconfirmed, but paying double indefinitely is worse than
		// committing. The new path was chosen because the old one was
		// failing.
		log.Printf("scheduler: handover to path %d unconfirmed after %v, committing anyway", s.switchingTo, elapsed.Round(time.Millisecond))
	case !s.stillEligible(s.switchFrom, eligible):
		// The path being left has gone entirely, so there is nothing left
		// to make before breaking.
		log.Printf("scheduler: handover to path %d completed early, path %d is gone", s.switchingTo, s.switchFrom)
	default:
		return // still overlapping
	}

	s.primary, s.havePrimary = s.switchingTo, true
	s.switching = false
}

// buildTx turns the settled primary into the actual list of paths a packet
// goes out of, applying the duplication policy.
func (s *scheduler) buildTx(d *decision, c config.Config, eligible []scored, sendable map[uint8]bool) {
	d.primary, d.havePrimary = s.primary, s.havePrimary
	d.switching, d.switchingTo = s.switching, s.switchingTo

	// Principle 5, and the most important branch in this file. With no
	// path in a usable state the measurements have stopped being able to
	// help, and the choice is between sending nothing and sending
	// everywhere. Sending everywhere at least has a chance.
	if len(eligible) == 0 || !s.havePrimary {
		for _, id := range s.candidates() {
			d.tx = append(d.tx, id)
		}
		sort.Slice(d.tx, func(i, j int) bool { return d.tx[i] < d.tx[j] })
		d.blind = len(d.tx) > 0
		d.reason = "no usable path, sending on everything bound"

		// Blind mode sprays every class alike. There is no measurement
		// left to tell them apart with, so withholding bulk would be
		// acting on a distinction nothing can currently support.
		d.txBulk = append(d.txBulk, d.tx...)
		d.txTrans = append(d.txTrans, d.tx...)
		return
	}

	d.tx = append(d.tx, s.primary)

	// Transactional takes the primary and stops there, whatever
	// duplication the branches below add for real-time.
	d.txTrans = []uint8{s.primary}

	// Bulk rides the primary and stops there, whatever follows. Every
	// branch below adds paths for redundancy, and redundancy is for the
	// call.
	d.txBulk = []uint8{s.primary}

	if s.switching && sendable[s.switchingTo] {
		// Make-before-break, which scope-v1.md scopes to real-time
		// explicitly. Bulk stays where it is until the switch commits:
		// a download does not need both copies to survive a handover,
		// TCP will sort out what it misses, and paying double for it
		// during exactly the window the call needs the capacity is the
		// wrong trade.
		d.tx = append(d.tx, s.switchingTo)
		d.reason = "make-before-break handover (real-time only)"
		return
	}

	// What a second copy of the stream would cost the path that took it.
	// The primary's own send rate is the honest figure: a duplicate is, by
	// definition, exactly as much traffic as the original.
	load := s.offeredKbps(eligible)

	switch c.DuplicateMode {
	case config.DuplicateAlways:
		skipped := 0
		for _, sc := range eligible {
			if sc.m.id == s.primary {
				continue
			}
			if !s.canTake(sc, load, c) {
				skipped++
				continue
			}
			d.tx = append(d.tx, sc.m.id)
		}
		d.reason = "duplicating real-time on every usable path"
		if skipped > 0 {
			d.reason = "duplicating real-time on every path with the capacity for it"
		}

	case config.DuplicateUnstable:
		if mach := s.machines[s.primary]; mach != nil && mach.state == stateUnstable {
			// Only one spare copy, and it goes to the best path that can
			// actually take it. Duplication is insurance, and taking out
			// three policies on a link that has none to spare is how the
			// insurance becomes the accident - which is precisely what a
			// 512k standby link does when a download is mirrored onto it
			// because it looked healthy while carrying nothing.
			for _, sc := range eligible {
				if sc.m.id == s.primary || !s.canTake(sc, load, c) {
					continue
				}
				d.tx = append(d.tx, sc.m.id)
				break
			}
			if len(d.tx) > 1 {
				d.reason = "duplicating real-time while the chosen path is degraded"
			} else {
				d.reason = "chosen path degraded, no path has the capacity to duplicate onto"
			}
			return
		}
		d.reason = "single path"

	default:
		d.reason = "single path"
	}
}

func (s *scheduler) stillEligible(id uint8, eligible []scored) bool {
	_, ok := s.metricOf(id, eligible)
	return ok
}

func (s *scheduler) metricOf(id uint8, eligible []scored) (pathMetric, bool) {
	for _, sc := range eligible {
		if sc.m.id == id {
			return sc.m, true
		}
	}
	return pathMetric{}, false
}

func (s *scheduler) scoreOf(id uint8, eligible []scored) (float64, bool) {
	for _, sc := range eligible {
		if sc.m.id == id {
			return sc.score, true
		}
	}
	return 0, false
}
