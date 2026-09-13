package relay

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
	"github.com/anthonysecco/OpenMultiPath/internal/usage"
)

// The cascade is v0.2's bulk scheduler (v0.2-design.md, section 5).
//
// v0.1 placed bulk per flow: each download was hashed onto one path of a
// load-balancing set, so a single flow never exceeded a single link, and the
// call's path was protected by a gate that dropped all bulk the moment that
// path queued. The cascade places bulk per packet instead:
//
//   - it fills the slowest usable path first, where latency costs a download
//     nothing, and spills onto the next faster path only once that one is
//     full, and so on down to the path carrying the call, which is always
//     last;
//   - a path is full when its shaper is backed up (D-055): it is held to 95%
//     of its measured speed, and bulk queued behind that past shaperRoom goes
//     on to the next path. A path never measured is unshaped, so it never
//     reads full and never spills - an unmeasured link is taken as unlimited;
//   - the far end puts each flow back in order (reseq.go).
//
// There used to be a controller per path here, cutting each path's allowance
// on the standing queue and loss the far end reported and growing it back
// after a clean run. D-055 removed it: a link's speed is what it measured,
// not what its queue suggests.
//
// Real-time traffic on a path changes only where that path sits in the fill
// order: last. It never throttles or holds bulk back. The call's path is
// filled like every other path, and with every path backed up bulk overflows
// onto the first path in the order rather than being dropped here. That is
// the owner's rule (2026-09-12), and it replaces admission control's gate
// outright in cascade mode (S7); flow mode keeps the gate, being v0.1
// exactly.
//
// It is only ever active when every one of these holds: the operator has not
// switched it off (bulk_scheduler), the peer can resequence (wire version 3),
// classes are real (above WireGuard), and the scheduler is not spraying
// blind. Otherwise bulk is placed exactly as v0.1 placed it. Spreading a flow
// into a receiver that cannot reorder it is how D-044's first live test fell
// to 4 Mbps.

// cascadeMember is one path the cascade may put bulk on, in fill order.
type cascadeMember struct {
	id         uint8
	protected  bool    // carries real-time or transactional traffic; always last
	shapedKbps float64 // what its shaper holds it to; 0 is unshaped
	sentKbps   float64 // bulk it carried over the last evaluation
}

// cascadeSwapTicks is how many evaluations running a slower path must have
// been slower before it overtakes the one ahead.
const cascadeSwapTicks = 5

// cascadeInactive says why the cascade is not running, or "" when it may.
func (s *scheduler) cascadeInactive(d *decision, c config.Config) string {
	switch {
	case c.BulkScheduler != config.BulkCascade:
		return "bulk_scheduler is flow"
	case !s.classifying.Load():
		return "not classifying, so bulk cannot be told from a call"
	case s.peerResequences == nil || !s.peerResequences():
		return "the peer cannot resequence (wire version below 3)"
	case d.blind:
		return "no usable path"
	case !d.havePrimary:
		return "no primary chosen yet"
	}
	return ""
}

// healthyForCascade is who may take spread bulk: not red, not down, and
// delivering - quality over the reported send direction and not flapping
// (D-046).
//
// Not "stable", which v0.1's spread required (D-044). There it kept a
// radio-lossy link out of a hash that would hand it half the flows for
// their whole lives. Here the controller cuts a lossy link's allowance on
// its own, and requiring stable excludes exactly the path the cascade is
// filling: a queue our own bulk built is enough for the state machine to
// call a path unstable, and the lab run that found this lost its whole
// second link to it.
func healthyForCascade(now time.Duration, sc scored, c config.Config) bool {
	if sc.m.budget.Band == usage.Red || sc.mach.state == stateDown {
		return false
	}
	return deliveringForSpread(now, sc, c)
}

// baseDelayMs is a path's delay with nothing queued on it: half its round-
// trip floor, or half the live round trip before a floor exists. What the
// cascade orders and gates on.
//
// Not the scoring delay, which adds the reported p95 tail. That tail holds
// whatever queue our own bulk built, for as long as the last two hundred
// samples remember it, so ordering on it would move bulk off a path because
// bulk was on it - the cascade chasing its own queue - and the delta gate
// would drop a link for minutes after one burst. Queueing is the
// controller's to manage; the order is about the links.
func baseDelayMs(m pathMetric) float64 {
	if m.rttFloorMs > 0 {
		return m.rttFloorMs / 2
	}
	return m.rttMs / 2
}

// buildCascade decides this evaluation's cascade and publishes it on d.
func (s *scheduler) buildCascade(now time.Duration, d *decision, c config.Config, eligible []scored) {
	if why := s.cascadeInactive(d, c); why != "" {
		d.cascadeWhy = why
		s.setCascadeActive(false, why)
		s.cascadeOrder = nil
		s.swapFor = nil
		return
	}

	byID := make(map[uint8]scored, len(eligible))
	for _, sc := range eligible {
		byID[sc.m.id] = sc
	}
	base := func(id uint8) float64 { return baseDelayMs(byID[id].m) }
	protected := make(map[uint8]bool, len(d.tx))
	for _, id := range d.tx {
		protected[id] = true
	}

	// The delta gate: a path so far behind the call's path that its packets
	// would arrive after the far end had given up waiting for them is worth
	// nothing to a spread flow.
	primaryDelay := base(d.primary)
	maxBehind := float64(c.ResequencerMaxHoldMs - c.ResequencerHoldMarginMs)
	inReach := func(sc scored) bool { return baseDelayMs(sc.m)-primaryDelay <= maxBehind }

	// D-045's size gate, with the bar taken over every healthy path, the
	// call's included. v0.1 left the call's path out of the bar because bulk
	// was kept off it; the cascade fills it last, so it is a peer like any
	// other. Leaving it out compared the vehicle's 3 Mbit Starlink tier with
	// nothing but itself, and the cascade filled that first while a 55 Mbit
	// AT&T link waited behind it.
	var bestKbps float64
	for _, sc := range eligible {
		if healthyForCascade(now, sc, c) && sc.m.shapedKbps > bestKbps {
			bestKbps = sc.m.shapedKbps
		}
	}
	var members []scored
	for _, sc := range eligible {
		if protected[sc.m.id] || !healthyForCascade(now, sc, c) ||
			undersizedForSpread(sc.m.shapedKbps, bestKbps, c) || !inReach(sc) {
			continue
		}
		members = append(members, sc)
	}
	// No forest-canopy fallback (D-033). Placed per flow, a flapping link was a
	// fine home for traffic that can wait: each flow took what got through.
	// Spread per packet, a flapping link stalls every flow it touches at the
	// far end, waiting for bursts of packets that never arrive. On the vehicle
	// a flapping Starlink put back first in line this way took a single upload
	// from 68 Mbit to 0.1. Unstable links that are not flapping are already
	// members; a flapping one waits until it stops.

	order := s.orderCascade(c, members)
	sent := s.bulkRates(now)

	d.cascade = d.cascade[:0]
	d.cascadeIDs = d.cascadeIDs[:0]
	add := func(id uint8, prot bool) {
		d.cascade = append(d.cascade, cascadeMember{id: id, protected: prot, shapedKbps: byID[id].m.shapedKbps, sentKbps: sent[id]})
		d.cascadeIDs = append(d.cascadeIDs, id)
	}
	for _, id := range order {
		add(id, false)
	}
	for _, id := range d.tx {
		if _, ok := byID[id]; ok {
			add(id, true)
		}
	}

	// Where bulk goes once every path is backed up: the first path in fill
	// order. A download queues where it would have gone first anyway, and the
	// call's path takes only its own share - unless it is the only path, when
	// it takes everything.
	d.overflowIdx = 0

	d.cascadeOn = len(d.cascade) > 0
	if !d.cascadeOn {
		d.cascadeWhy = "no path to place bulk on"
	}
	s.setCascadeActive(d.cascadeOn, d.cascadeWhy)
}

// orderCascade sorts the unprotected members slowest first, holding the
// previous order against small differences (v0.2-design.md, section 5.2).
func (s *scheduler) orderCascade(c config.Config, members []scored) []uint8 {
	delay := make(map[uint8]float64, len(members))
	for _, sc := range members {
		delay[sc.m.id] = baseDelayMs(sc.m)
	}

	// Keep the previous order for whoever is still a member, and slot newcomers
	// in where their delay puts them.
	order := make([]uint8, 0, len(members))
	for _, id := range s.cascadeOrder {
		if _, ok := delay[id]; ok {
			order = append(order, id)
		}
	}
	placed := make(map[uint8]bool, len(order))
	for _, id := range order {
		placed[id] = true
	}
	newcomers := make([]uint8, 0)
	for _, sc := range members {
		if !placed[sc.m.id] {
			newcomers = append(newcomers, sc.m.id)
		}
	}
	sort.Slice(newcomers, func(i, j int) bool { return delay[newcomers[i]] > delay[newcomers[j]] })
	for _, id := range newcomers {
		at := len(order)
		for i, other := range order {
			if delay[id] > delay[other] {
				at = i
				break
			}
		}
		order = append(order, 0)
		copy(order[at+1:], order[at:])
		order[at] = id
	}

	// One pass of hysteresis-guarded swaps. Two adjacent members trade places
	// only once the one behind has been the slower by more than the margin for
	// several evaluations running.
	hyst := float64(c.CascadeOrderHysteresisMs)
	swaps := make(map[[2]uint8]int)
	for i := 0; i+1 < len(order); i++ {
		a, b := order[i], order[i+1]
		if delay[b]-delay[a] <= hyst {
			continue
		}
		key := [2]uint8{a, b}
		n := s.swapFor[key] + 1
		if n < cascadeSwapTicks {
			swaps[key] = n
			continue
		}
		order[i], order[i+1] = b, a
		log.Printf("cascade: %s is now filled before %s (%.0f ms against %.0f ms out)",
			s.pathName(b), s.pathName(a), delay[b], delay[a])
		i++ // the pair just swapped is settled for this evaluation
	}
	s.swapFor = swaps

	s.cascadeOrder = append(s.cascadeOrder[:0], order...)
	return order
}

// bulkRates reads how much bulk each path carried since the last evaluation,
// in kbps, from the counters the data path keeps.
func (s *scheduler) bulkRates(now time.Duration) map[uint8]float64 {
	out := make(map[uint8]float64)
	elapsed := now - s.lastBulkAt
	first := s.lastBulkAt == 0
	s.lastBulkAt = now
	for i := range s.bulkBytes {
		total := s.bulkBytes[i].Load()
		delta := total - s.lastBulkBytes[i]
		s.lastBulkBytes[i] = total
		if first || elapsed <= 0 || delta == 0 {
			continue
		}
		out[uint8(i)] = float64(delta) * 8 / 1000 / elapsed.Seconds()
	}
	return out
}

// setCascadeActive logs the cascade starting and stopping.
func (s *scheduler) setCascadeActive(on bool, why string) {
	if s.cascadeLogged && s.cascadeWasOn == on && s.cascadeWhyLogged == why {
		return
	}
	first := !s.cascadeLogged
	s.cascadeLogged, s.cascadeWasOn, s.cascadeWhyLogged = true, on, why
	switch {
	case on:
		log.Printf("cascade: active, bulk spread per packet")
	case first && why == "no primary chosen yet":
		// The ordinary first evaluations; not worth a line.
	default:
		log.Printf("cascade: inactive (%s), bulk placed per flow", why)
	}
}

// pickCascade chooses the one path a bulk packet goes out of
// (v0.2-design.md, section 5.3). It never drops.
//
// The first path in fill order whose shaper has room takes it (D-055). When
// every path is backed up the packet goes to the first in the order
// (decision.overflowIdx), and the sending TCP finds the aggregate's limit from
// the shaper's queue, as it would at any router. The first version of the
// cascade dropped here whenever every allowance was spent, which made the
// tunnel a policer: TCP read the drops as the aggregate being full, never
// pushed past the first link, and the lab measured a two-link cascade carrying
// less than one link did per flow.
func (s *scheduler) pickCascade(d *decision, size int) ([]uint8, bool) {
	for i, m := range d.cascade {
		if s.hasRoom == nil || s.hasRoom(m.id) {
			s.bulkBytes[m.id].Add(uint64(size))
			return d.cascadeIDs[i : i+1], true
		}
	}
	if len(d.cascade) == 0 {
		return nil, false // not reachable: txForPacket only calls this with a cascade
	}
	i := d.overflowIdx
	s.bulkBytes[d.cascade[i].id].Add(uint64(size))
	s.overflowed.Add(1)
	return d.cascadeIDs[i : i+1], true
}

// txForPacket is what the data path calls: the paths one packet goes out of,
// or false when it is to be dropped at the ingress. It differs from txFor only
// while the cascade is active, where bulk is placed per packet and
// transactional returns to the primary alone.
func (s *scheduler) txForPacket(class uint8, flow uint32, size int) ([]uint8, bool) {
	d := s.cur.Load()
	if !d.cascadeOn || class == protocol.ClassRealtime {
		return s.txFor(class, flow), true
	}
	if class == protocol.ClassBulk {
		return s.pickCascade(d, size)
	}
	// Transactional, and anything unplaced: the call's link, alone. S3 wants
	// page loads responsive on the low-latency path, and a request split
	// across links would be resequenced for nothing.
	if len(d.txTrans) > 0 {
		return d.txTrans, true
	}
	return d.tx, true
}

// describeCascade renders the cascade for the log.
func describeCascade(d *decision, name func(uint8) string) string {
	if !d.cascadeOn {
		return "per flow (" + d.cascadeWhy + ")"
	}
	parts := make([]string, 0, len(d.cascade))
	for _, m := range d.cascade {
		cap := "unshaped"
		if m.shapedKbps > 0 {
			cap = fmt.Sprintf("shaped to %.0f kbps", m.shapedKbps)
		}
		tag := ""
		if m.protected {
			tag = ", call's path"
		}
		parts = append(parts, fmt.Sprintf("%s (%s, carrying %.0f kbps%s)", name(m.id), cap, m.sentKbps, tag))
	}
	return strings.Join(parts, " -> ")
}
