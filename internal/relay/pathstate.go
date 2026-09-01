package relay

import (
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
)

// The three-state path machine from protocol.md.
//
// The split between this file and quality.go is the important part of the
// design and is easy to lose. This file answers "is the path healthy",
// judged only against the path's own thresholds. quality.go answers "which
// path is best", by comparing paths against each other. Conflating them
// produces a machine that demotes a satellite link for being a satellite
// link: 600 ms of honest, steady, unavoidable latency is a poor score, but
// it is not instability, and a path that is merely slow must stay eligible
// because on some evenings it is all there is.
type linkState uint8

const (
	// stateDown requires both probe failure and data-plane silence, so a
	// path nobody has sent anything down is never declared dead for
	// failing to answer a question it was not asked.
	stateDown linkState = iota

	// stateUnstable is degraded but still eligible, carrying a penalty.
	// Explicitly not cut off: principle 5 says fail to a working state,
	// and a degraded path is a working state.
	stateUnstable

	// stateStable is meeting every threshold and eligible for everything.
	stateStable
)

func (s linkState) String() string {
	switch s {
	case stateStable:
		return "stable"
	case stateUnstable:
		return "unstable"
	default:
		return "down"
	}
}

// pathMetric is everything the machine and the scoring need about one path
// at one instant. It is assembled under the session lock and then handed
// over by value, so evaluation never holds the lock the data path needs.
type pathMetric struct {
	id   uint8
	name string

	// managed says this end owns the physical socket, so bound is
	// meaningful. The responder learns its paths from what arrives and has
	// no socket of its own to report on.
	managed bool
	bound   bool

	// silentFor is how long since anything arrived on this path, and
	// sentSinceHeard how many packets we have put into it in that time.
	// Both are needed to call a path down.
	silentFor      time.Duration
	sentSinceHeard uint64

	// confirmedAt is when the peer last echoed a packet we sent on this
	// path, which is the only direct evidence that our transmissions are
	// arriving. Receiving on a path proves the reverse direction only, and
	// paths are asymmetric.
	confirmedAt time.Duration

	rttMs        float64
	p95SpreadMs  float64
	jitterMs     float64
	queueDelayMs float64
	recentLoss   float64
	burstRatio   float64

	// thin means too few samples to conclude anything. A thin path is
	// never promoted and never demoted on its statistics.
	thin bool

	// unusable means the path has been probed and cannot carry the tunnel
	// floor. Distinct from "not yet probed", which is not a fault.
	unusable bool
}

// machine is the hysteresis state for one path.
type machine struct {
	state     linkState
	reason    string
	changedAt time.Duration

	breaching int // consecutive evaluations failing a threshold
	clean     int // consecutive evaluations passing all of them

	// transitions holds when this path last changed state, pruned to the
	// flap window. A path that oscillates is penalised for oscillating,
	// independently of how good it looks at this instant.
	transitions []time.Duration

	// demoteUntil holds a path out of stable on an out-of-band signal -
	// Starlink obstruction telemetry, a collapsing cellular SINR. D-017 is
	// firm that such signals may demote and may never promote, because
	// they lead the loss statistics but prove nothing about whether the
	// path currently works.
	demoteUntil time.Duration
}

// evaluate advances the machine one interval and reports whether the state
// changed.
func (m *machine) evaluate(now time.Duration, p pathMetric, c config.Config) bool {
	want, why := m.assess(now, p, c)
	if want == m.state {
		return false
	}
	m.state, m.reason, m.changedAt = want, why, now
	m.transitions = append(m.transitions, now)
	m.pruneTransitions(now, c.FlapWindow())
	return true
}

// assess decides what state the path should be in, without changing
// anything.
func (m *machine) assess(now time.Duration, p pathMetric, c config.Config) (linkState, string) {
	// A link with no socket is not a measurement problem. It is a modem
	// that has not registered or a lease that has gone, and no amount of
	// hysteresis makes it carry a packet.
	if p.managed && !p.bound {
		m.breaching, m.clean = 0, 0
		return stateDown, "link down"
	}

	// Down needs both halves. Silence alone is the ordinary state of an
	// idle path; silence while we are actively putting packets into it is
	// a path that has stopped working.
	if p.silentFor >= c.DownSilence() && p.sentSinceHeard >= uint64(c.DownProbePackets) {
		m.breaching, m.clean = 0, 0
		return stateDown, "silent while being probed"
	}

	// Recovery is deliberately to unstable, never straight to stable. A
	// path that has just come back has proved only that it can deliver a
	// packet, and steering a call onto it on that evidence is precisely
	// the flapping trap of emerging from a canyon.
	if m.state == stateDown {
		m.breaching, m.clean = 0, 0
		return stateUnstable, "recovering"
	}

	// A path that cannot carry the tunnel floor is a fault to be flagged,
	// not a condition to be accommodated. It stays eligible, because one
	// undersized path beats none at all, but it can never be called
	// stable.
	if p.unusable {
		m.clean = 0
		return stateUnstable, "below the tunnel floor"
	}

	// Out-of-band demotion caps the path at unstable for its hold.
	if now < m.demoteUntil {
		m.clean = 0
		if m.state == stateStable {
			return stateUnstable, "out-of-band signal"
		}
		return m.state, m.reason
	}

	// Thin statistics conclude nothing in either direction. Ten packets
	// tells you nothing about a loss rate, so it must not demote a working
	// path, and it must certainly not promote one.
	if p.thin {
		m.breaching, m.clean = 0, 0
		return m.state, m.reason
	}

	if why, breached := breach(p, c); breached {
		m.clean = 0
		m.breaching++
		if m.breaching >= c.DemoteIntervals && m.state == stateStable {
			return stateUnstable, why
		}
		return m.state, m.reason
	}

	m.breaching = 0
	m.clean++
	if m.clean >= c.PromoteIntervals && m.state == stateUnstable {
		return stateStable, "clean"
	}
	return m.state, m.reason
}

// breach reports whether a path is failing any of its own thresholds, and
// which one first. Every test here is absolute: none of them compares the
// path against another path.
func breach(p pathMetric, c config.Config) (string, bool) {
	switch {
	case p.recentLoss > float64(c.UnstableLossPercent):
		return "loss", true
	case p.queueDelayMs > float64(c.UnstableQueueDelayMs):
		return "queue delay", true
	case p.jitterMs > float64(c.UnstableJitterMs):
		return "jitter", true
	}
	return "", false
}

// demote holds a path out of stable for a while on an out-of-band signal.
// Nothing calls it yet: the Starlink dish's obstruction telemetry and
// ModemManager's RSRP are step 6's natural companions but are not wired up.
// The seam exists so that when they are, D-017's one-way rule is enforced
// here rather than trusted to the caller.
func (m *machine) demote(now time.Duration, hold time.Duration) {
	if until := now + hold; until > m.demoteUntil {
		m.demoteUntil = until
	}
}

// pruneTransitions drops state changes that have aged out of the flap
// window.
func (m *machine) pruneTransitions(now time.Duration, window time.Duration) {
	cut := 0
	for cut < len(m.transitions) && now-m.transitions[cut] > window {
		cut++
	}
	m.transitions = m.transitions[cut:]
}

// flapping reports whether this path has changed state too often to be
// trusted with anything that would notice.
//
// This is the forest-canopy case: intermittent obstruction rather than
// clean blockage, an hour of a link coming and going. The correct
// behaviour is to stop trying, and this is what makes the scheduler stop.
func (m *machine) flapping(now time.Duration, c config.Config) bool {
	m.pruneTransitions(now, c.FlapWindow())
	return len(m.transitions) >= c.FlapThreshold
}

// score is the path's R factor once its state has been taken into account.
// A down path scores zero and is not a candidate at all.
func (m *machine) score(now time.Duration, p pathMetric, c config.Config) float64 {
	if m.state == stateDown {
		return 0
	}
	r := rFactor(
		effectiveDelayMs(p.rttMs, p.p95SpreadMs, float64(c.BaseDelayMs)),
		p.recentLoss,
		p.burstRatio,
	)
	if m.state == stateUnstable {
		r -= float64(c.UnstablePenaltyR)
	}
	if m.flapping(now, c) {
		r -= float64(c.FlapPenaltyR)
	}
	return clampFloat(r, 0, 100)
}
