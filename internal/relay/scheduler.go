package relay

import (
	"log"
	"sort"
	"sync/atomic"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
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
	// tx is the paths a data packet is sent on, in order.
	tx []uint8

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

	switching      bool
	switchFrom     uint8
	switchingTo    uint8
	switchingSince time.Duration
}

func newScheduler(sess *session, cfg *config.Holder, candidates func() []uint8) *scheduler {
	s := &scheduler{
		sess:       sess,
		cfg:        cfg,
		candidates: candidates,
		source:     sess.metrics,
		machines:   make(map[uint8]*machine),
	}
	s.cur.Store(emptyDecision)
	return s
}

// current is the decision in force. Never nil.
func (s *scheduler) current() *decision { return s.cur.Load() }

// txPaths is the data path's entire interface to the scheduler: the paths
// this packet should go out of.
func (s *scheduler) txPaths() []uint8 { return s.cur.Load().tx }

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
		if mach.evaluate(now, p, c) {
			log.Printf("path %d (%s): %s (%s)", p.id, p.name, mach.state, mach.reason)
		}
		all = append(all, scored{
			m:       p,
			mach:    mach,
			score:   mach.score(now, p, c),
			delayMs: effectiveDelayMs(p.rttMs, p.p95SpreadMs, float64(c.BaseDelayMs)),
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

	for _, sc := range all {
		d.views[sc.m.id] = pathView{
			State:       sc.mach.state.String(),
			Reason:      sc.mach.reason,
			Score:       sc.score,
			RFactor:     rFactor(effectiveDelayMs(sc.m.rttMs, sc.m.p95SpreadMs, float64(c.BaseDelayMs)), sc.m.recentLoss, sc.m.burstRatio),
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
		s.challengerFor = 0
		return
	}

	// The absolute floor. protocol.md is firm that a real-time flow should
	// move because its current path has become inadequate, not because
	// something else looks marginally nicer - so a challenger with a
	// better score is not on its own a reason to move.
	if cur < float64(c.MinAcceptableR) && best.score > cur {
		s.beginSwitch(now, best.m.id, "current path below the floor")
		return
	}

	if best.score > cur+float64(c.SwitchMarginR) {
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
	s.challengerFor = 0
}

// adopt takes a path as primary with no overlap. Used only when there is no
// working path to overlap with, since there is nothing to make before
// breaking.
func (s *scheduler) adopt(id uint8, why string) {
	if s.havePrimary && s.primary == id {
		return
	}
	log.Printf("scheduler: primary -> path %d (%s)", id, why)
	s.primary, s.havePrimary = id, true
	s.switching, s.challengerFor = false, 0
}

// beginSwitch starts a make-before-break handover: both paths carry the
// traffic until the new one is confirmed. Never cut then connect - a gap is
// audible.
func (s *scheduler) beginSwitch(now time.Duration, to uint8, why string) {
	log.Printf("scheduler: handover path %d -> path %d (%s), overlapping", s.primary, to, why)
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
		log.Printf("scheduler: handover to path %d abandoned, it is no longer usable", s.switchingTo)
		s.switching = false
		return
	}

	// Confirmation means the peer echoed something we sent on the new
	// path after the handover began. Receiving on a path proves only the
	// reverse direction, and a path can be fine inbound and dead outbound.
	confirmed := target.confirmedAt > s.switchingSince

	switch {
	case confirmed && elapsed >= c.MBBMin():
		log.Printf("scheduler: handover to path %d confirmed after %v", s.switchingTo, elapsed.Round(time.Millisecond))
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
		return
	}

	d.tx = append(d.tx, s.primary)

	if s.switching && sendable[s.switchingTo] {
		d.tx = append(d.tx, s.switchingTo)
		d.reason = "make-before-break handover"
		return
	}

	switch c.DuplicateMode {
	case config.DuplicateAlways:
		for _, sc := range eligible {
			if sc.m.id != s.primary {
				d.tx = append(d.tx, sc.m.id)
			}
		}
		d.reason = "duplicating on every usable path"

	case config.DuplicateUnstable:
		if mach := s.machines[s.primary]; mach != nil && mach.state == stateUnstable {
			// Only one spare copy. Duplication is insurance, and taking
			// out three policies on a link that has none to spare is how
			// the insurance becomes the accident.
			for _, sc := range eligible {
				if sc.m.id != s.primary {
					d.tx = append(d.tx, sc.m.id)
					break
				}
			}
			d.reason = "duplicating while the chosen path is degraded"
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
