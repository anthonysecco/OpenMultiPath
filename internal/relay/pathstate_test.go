package relay

import (
	"testing"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
)

// healthy is a path meeting every threshold, with enough samples to be
// believed.
func healthy() pathMetric {
	return pathMetric{
		id:         0,
		bound:      true,
		managed:    true,
		rttMs:      40,
		jitterMs:   3,
		burstRatio: 1,
	}
}

// settle runs the machine from `now` until it reaches the wanted state, or
// fails. It returns the clock it reached and how many intervals it took.
//
// The clock is threaded through rather than restarted, because several of
// these tests turn on absolute times - an out-of-band hold expires at a
// wall-clock instant, not after a number of evaluations - and a helper that
// quietly rewound to zero would report those as passing.
func settle(t *testing.T, m *machine, p pathMetric, c config.Config, want linkState, now time.Duration, limit int) (time.Duration, int) {
	t.Helper()
	for i := 1; i <= limit; i++ {
		now += c.EvalInterval()
		m.evaluate(now, p, c)
		if m.state == want {
			return now, i
		}
	}
	t.Fatalf("path never reached %s within %d intervals from %v, stuck at %s (%s)",
		want, limit, now, m.state, m.reason)
	return now, 0
}

// A path starts down and has to earn its way up. Coming up assuming a path
// works is how a scheduler steers a call onto a link it has never measured.
func TestPathStartsDownAndMustEarnPromotion(t *testing.T) {
	c := config.Defaults()
	m := &machine{}

	if m.state != stateDown {
		t.Fatalf("a fresh path is %s, want down until something is measured", m.state)
	}

	_, took := settle(t, m, healthy(), c, stateStable, 0, 100)
	if took < c.PromoteIntervals {
		t.Errorf("path reached stable in %d intervals, faster than the %d clean ones required",
			took, c.PromoteIntervals)
	}
}

// Demotion has to be sustained. A single bad measurement is a bad
// measurement, not a degraded link.
func TestOneBadIntervalDoesNotDemote(t *testing.T) {
	c := config.Defaults()
	m := &machine{}
	now, _ := settle(t, m, healthy(), c, stateStable, 0, 100)

	bad := healthy()
	bad.recentLoss = float64(c.UnstableLossPercent) + 5

	m.evaluate(now+c.EvalInterval(), bad, c)
	if m.state != stateStable {
		t.Errorf("one bad interval demoted the path to %s; the breach has to be sustained", m.state)
	}
}

// The asymmetry is the point: a path that has just broken has proved much
// more than a path that has just come back.
func TestPromotionIsSlowerThanDemotion(t *testing.T) {
	c := config.Defaults()
	m := &machine{}
	now, _ := settle(t, m, healthy(), c, stateStable, 0, 100)

	bad := healthy()
	bad.queueDelayMs = float64(c.UnstableQueueDelayMs) + 50

	demoteTook := 0
	for i := 1; i <= 100; i++ {
		now += c.EvalInterval()
		m.evaluate(now, bad, c)
		if m.state == stateUnstable {
			demoteTook = i
			break
		}
	}
	if demoteTook == 0 {
		t.Fatal("a sustained queue-delay breach never demoted the path")
	}

	promoteTook := 0
	for i := 1; i <= 200; i++ {
		now += c.EvalInterval()
		m.evaluate(now, healthy(), c)
		if m.state == stateStable {
			promoteTook = i
			break
		}
	}
	if promoteTook == 0 {
		t.Fatal("a clean path never recovered to stable")
	}
	if promoteTook <= demoteTook {
		t.Errorf("promotion took %d intervals and demotion %d; promotion must be the slower of the two",
			promoteTook, demoteTook)
	}
}

// protocol.md is explicit: a path with no traffic must not be declared dead
// on probe loss alone. Silence only means something once we have actually
// put packets into it.
func TestSilenceAloneDoesNotKillAPath(t *testing.T) {
	c := config.Defaults()
	m := &machine{}
	settle(t, m, healthy(), c, stateStable, 0, 100)

	quiet := healthy()
	quiet.silentFor = c.DownSilence() * 10
	quiet.sentSinceHeard = 0 // nothing was ever asked of it

	m.evaluate(100*c.EvalInterval(), quiet, c)
	if m.state == stateDown {
		t.Error("an idle path was declared down without ever being probed")
	}
}

func TestSilenceWhileProbingDoesKillAPath(t *testing.T) {
	c := config.Defaults()
	m := &machine{}
	settle(t, m, healthy(), c, stateStable, 0, 100)

	dead := healthy()
	dead.silentFor = c.DownSilence()
	dead.sentSinceHeard = uint64(c.DownProbePackets)

	m.evaluate(100*c.EvalInterval(), dead, c)
	if m.state != stateDown {
		t.Errorf("a path silent under active probing is %s, want down", m.state)
	}
}

// A link with no socket is not a measurement problem, and no amount of
// hysteresis makes it carry a packet.
func TestUnboundLinkIsDownImmediately(t *testing.T) {
	c := config.Defaults()
	m := &machine{}
	settle(t, m, healthy(), c, stateStable, 0, 100)

	gone := healthy()
	gone.bound = false

	m.evaluate(100*c.EvalInterval(), gone, c)
	if m.state != stateDown {
		t.Errorf("an unbound link is %s, want down", m.state)
	}
	if m.reason != "link down" {
		t.Errorf("reason is %q, want it to name the link rather than the measurements", m.reason)
	}
}

// The flapping trap from the canyon walkthrough: a path returns, scores
// well on a handful of probes, and takes the call just before it is cut
// again. Recovery must land in unstable so promotion still has to be
// earned.
func TestRecoveryGoesToUnstableNotStraightToStable(t *testing.T) {
	c := config.Defaults()
	m := &machine{}
	settle(t, m, healthy(), c, stateStable, 0, 100)

	gone := healthy()
	gone.bound = false
	now := 100 * c.EvalInterval()
	m.evaluate(now, gone, c)

	now += c.EvalInterval()
	m.evaluate(now, healthy(), c)
	if m.state != stateUnstable {
		t.Errorf("a recovered path went straight to %s; it must re-earn stable", m.state)
	}
}

// Ten packets tells you nothing about a loss rate, in either direction.
func TestThinStatisticsNeitherPromoteNorDemote(t *testing.T) {
	c := config.Defaults()

	m := &machine{state: stateUnstable, reason: "recovering"}
	thin := healthy()
	thin.thin = true
	now := time.Duration(0)
	for i := 0; i < c.PromoteIntervals*3; i++ {
		now += c.EvalInterval()
		m.evaluate(now, thin, c)
	}
	if m.state != stateUnstable {
		t.Errorf("a thin path was promoted to %s on statistics too small to support it", m.state)
	}

	m = &machine{state: stateStable, reason: "clean"}
	thinBad := thin
	thinBad.recentLoss = 90
	for i := 0; i < c.DemoteIntervals*3; i++ {
		now += c.EvalInterval()
		m.evaluate(now, thinBad, c)
	}
	if m.state != stateStable {
		t.Errorf("a thin path was demoted to %s on statistics too small to support it", m.state)
	}
}

// The forest-canopy case. An hour of a link coming and going should end
// with the scheduler declining to use it, not retrying it forever.
func TestFlappingIsPenalisedIndependentlyOfCurrentQuality(t *testing.T) {
	c := config.Defaults()
	m := &machine{}
	now := time.Duration(0)

	// Drive it up and down until it has flapped past the threshold. The
	// path starts down, so the first unbound interval is not a transition
	// at all - hence looping on the count rather than on a fixed number.
	for i := 0; !m.flapping(now, c); i++ {
		if i > c.FlapThreshold*4 {
			t.Fatalf("only %d transitions after %d intervals of flapping", len(m.transitions), i)
		}
		p := healthy()
		if i%2 == 0 {
			p.bound = false
		}
		now += c.EvalInterval()
		m.evaluate(now, p, c)
	}

	// Let it come back, so it is eligible again and scoring for real - a
	// down path scores zero whatever its history, which would make the
	// comparison below vacuous.
	good := healthy()
	now += c.EvalInterval()
	m.evaluate(now, good, c)
	if m.state == stateDown {
		t.Fatalf("path did not recover after its link returned, still %s (%s)", m.state, m.reason)
	}

	// It now looks perfect, and must still be marked down for its history.
	penalised := m.score(now, good, c)
	steady := (&machine{state: m.state}).score(now, good, c)
	if penalised >= steady {
		t.Errorf("flapping path scored %.1f against an identical steady path's %.1f", penalised, steady)
	}

	// And the penalty must age out, or a link that misbehaved once at
	// breakfast is still being punished at dinner.
	later := now + c.FlapWindow() + time.Second
	if m.flapping(later, c) {
		t.Error("the flap penalty never expires")
	}
}

// D-017: out-of-band signals lead the loss statistics, which is why they
// may demote. They prove nothing about whether a path works, which is why
// they may never promote.
func TestOutOfBandSignalDemotesButNeverPromotes(t *testing.T) {
	c := config.Defaults()
	m := &machine{}
	settle(t, m, healthy(), c, stateStable, 0, 100)

	now := 100 * c.EvalInterval()

	// The hold has to outlast the promotion attempt below, or the test
	// proves only that holds expire.
	hold := c.EvalInterval()*time.Duration(c.PromoteIntervals)*4 + time.Second
	m.demote(now, hold)

	now += c.EvalInterval()
	m.evaluate(now, healthy(), c)
	if m.state != stateUnstable {
		t.Fatalf("an out-of-band demotion left the path %s, want unstable", m.state)
	}

	// While the hold stands, a perfect path must not climb back.
	for i := 0; i < c.PromoteIntervals*2; i++ {
		now += c.EvalInterval()
		m.evaluate(now, healthy(), c)
		if m.state == stateStable {
			t.Fatal("an out-of-band signal promoted a path; only measured performance may do that")
		}
	}

	// Once it lapses, measured performance may promote it again.
	settle(t, m, healthy(), c, stateStable, now+hold, 100)
}

// D-010: a path that cannot carry the tunnel floor is a fault to flag, not
// a condition to accommodate. It stays usable - one undersized path beats
// none - but it can never be called stable.
func TestPathBelowTheTunnelFloorNeverBecomesStable(t *testing.T) {
	c := config.Defaults()
	m := &machine{}

	small := healthy()
	small.unusable = true

	now := time.Duration(0)
	for i := 0; i < c.PromoteIntervals*3; i++ {
		now += c.EvalInterval()
		m.evaluate(now, small, c)
	}
	if m.state != stateUnstable {
		t.Errorf("a path below the tunnel floor is %s, want unstable so it is flagged but still usable", m.state)
	}
}

// Every threshold judges the path against itself. A satellite link's 600 ms
// is honest, unavoidable and not instability, and demoting it for being
// slow would take the only link there is on some evenings.
func TestASteadySlowPathIsStableNotUnstable(t *testing.T) {
	c := config.Defaults()
	m := &machine{}

	slow := healthy()
	slow.rttMs = 600
	slow.p95SpreadMs = 20

	settle(t, m, slow, c, stateStable, 0, 100)
}
