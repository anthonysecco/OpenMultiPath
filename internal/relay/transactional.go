package relay

import (
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
)

// Transactional migration (D-064): a relief valve for transactional traffic
// while the cascade runs.
//
// In cascade mode transactional rides the primary, which is right for a page
// load - the shortest round trip - and wrong for an aggregate that outgrows the
// primary. A speed test's many parallel connections mostly classify as
// transactional, since no one of them sustains the bulk threshold for the
// dwell, and with Starlink's ~560 kbps standby tier as primary all of it piled
// onto that one link with a multi-megabit one idle beside it.
//
// So each transactional flow is remembered on the one path it rides, and moved
// - the whole flow, never a packet at a time - once that path's transactional
// band backs up, onto the best path that still has room. It stays there until
// that path fills too. Because a flow lives on exactly one path at any moment,
// nothing needs resequencing: a move is one reordering event, which TCP takes
// from an ordinary route change, never the sustained interleaving that D-044's
// first spread collapsed on.
//
// Rejected: spilling transactional per packet, the cascade reversed. It needs
// the resequencer, whose hold would tax exactly the latency-sensitive traffic
// this class exists to protect.
//
// Where a flow may go is transOrder: the primary first, then every other path
// healthy and big enough to take a heavy flow, in the scheduler's own ranking.
// That ranking is score, then scoring delay - between healthy links, lowest
// latency first - and it is the same ranking that picks the primary, so a moved
// flow lands on the path transactional would have chosen had the primary not
// been full. Scoring delay rather than the cascade's base delay on purpose: a
// move is triggered by congestion, so a destination's own congestion should
// count against it.

// transMoveHold is how long a flow that has just moved stays put however its
// new path reads. Without it a flow too big for either of two links bounces
// between them as each drains behind it, reordering on every bounce - D-033's
// "paying for the move over and over". A path leaving transOrder still moves
// its flows at once.
const transMoveHold = 2 * time.Second

// transFlow is where one transactional flow is riding.
type transFlow struct {
	path      uint8
	lastSeen  time.Duration
	heldUntil time.Duration // zero for a flow never moved
}

// buildTransactional publishes where transactional flows may ride this
// evaluation. Only while the cascade runs: in flow mode txFor already spreads
// transactional per flow (D-044), and that is v0.1 exactly.
func (s *scheduler) buildTransactional(now time.Duration, d *decision, c config.Config, eligible []scored) {
	d.transOrder = d.transOrder[:0]
	d.transIdle = time.Duration(c.ClassifyFlowIdleSeconds) * time.Second
	d.transMaxFlows = c.ClassifyMaxFlows
	if !d.cascadeOn {
		return
	}

	// The same membership as the cascade's, less the delta gate, which exists
	// for the resequencer and nothing here waits on one. Health (D-046): a flow
	// moved onto a link losing most of what it is given is worse off than one
	// queued on a link that is merely full. Size (D-045): a flow that moves is
	// by definition one that filled a path, and a link an eighth the size of
	// the best would be full the moment it arrived.
	var bestKbps float64
	for _, sc := range eligible {
		if healthyForCascade(now, sc, c) && sc.m.shapedKbps > bestKbps {
			bestKbps = sc.m.shapedKbps
		}
	}
	d.transOrder = append(d.transOrder, d.primary)
	for _, sc := range eligible {
		if sc.m.id == d.primary || !healthyForCascade(now, sc, c) ||
			undersizedForSpread(sc.m.shapedKbps, bestKbps, c) {
			continue
		}
		d.transOrder = append(d.transOrder, sc.m.id)
	}
}

// placeTransactional chooses the one path a transactional packet goes out of.
// Called only from the data path goroutine, which owns transFlows the way it
// owns the flow sequences.
func (s *scheduler) placeTransactional(d *decision, flow uint32) []uint8 {
	order := d.transOrder
	if len(order) < 2 || s.now == nil {
		// Nowhere to move to. Nothing is remembered either: a flow first seen
		// here is placed afresh, primary first, once a second path appears.
		return d.txTrans
	}
	now := s.now()
	s.sweepTransFlows(now, d.transIdle)

	room := func(id uint8) bool { return s.transRoom == nil || s.transRoom(id) }
	withRoom := func() int {
		for i, id := range order {
			if room(id) {
				return i
			}
		}
		return -1
	}

	f, known := s.transFlows[flow]
	// Idle past the timeout is not this conversation: port pairs get reused,
	// as the classifier's own flow table says.
	if known && now-f.lastSeen > d.transIdle {
		known = false
	}

	if !known {
		i := withRoom()
		if i < 0 {
			i = 0 // every path is full: the primary, as before D-064
		}
		if s.transFlows == nil {
			s.transFlows = make(map[uint32]*transFlow)
		}
		if f != nil {
			*f = transFlow{path: order[i], lastSeen: now}
		} else if len(s.transFlows) < d.transMaxFlows {
			s.transFlows[flow] = &transFlow{path: order[i], lastSeen: now}
		}
		return order[i : i+1]
	}
	f.lastSeen = now

	at := -1
	for i, id := range order {
		if id == f.path {
			at = i
			break
		}
	}
	// Stickiness: a flow leaves a path only when it is actually full, never for
	// a better one.
	if at >= 0 && (now < f.heldUntil || room(f.path)) {
		return order[at : at+1]
	}

	i := withRoom()
	switch {
	case i < 0 && at >= 0:
		// Every path is full. Moving would buy a reordering and no room.
		return order[at : at+1]
	case i < 0:
		i = 0 // its path has gone and nothing has room: back to the primary
	}
	f.path, f.heldUntil = order[i], now+transMoveHold
	s.transMoved.Add(1)
	return order[i : i+1]
}

// sweepTransFlows forgets flows idle past the timeout, at most once a quarter
// of it, so the table stays bounded without a walk on every packet.
func (s *scheduler) sweepTransFlows(now, idle time.Duration) {
	if now < s.transSweepAt {
		return
	}
	s.transSweepAt = now + idle/4
	for k, f := range s.transFlows {
		if now-f.lastSeen > idle {
			delete(s.transFlows, k)
		}
	}
}
