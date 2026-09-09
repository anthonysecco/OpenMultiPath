package relay

import (
	"testing"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
)

// bwDriver runs an estimate forward the way the evaluation loop does: a
// tick at a time, with a rate offered onto the path and a round trip
// observed coming back.
type bwDriver struct {
	b   bwEstimate
	now time.Duration
	c   config.Config
}

func newBWDriver() *bwDriver {
	return &bwDriver{c: config.Defaults()}
}

// run advances for d, offering kbps onto the path each tick and reporting
// the given round trip. downQueueMs is what the receive direction is
// already known to be contributing.
func (d *bwDriver) run(dur time.Duration, kbps, rttMs, downQueueMs float64) {
	const tick = 200 * time.Millisecond
	for end := d.now + dur; d.now < end; {
		d.b.noteSent(int(kbps * 1000 / 8 * tick.Seconds()))
		d.now += tick
		d.b.observe(d.now, rttMs, downQueueMs, peerView{}, d.c)
	}
}

// idle advances time with nothing but the odd probe on the path.
func (d *bwDriver) idle(dur time.Duration, rttMs float64) {
	d.run(dur, 12, rttMs, 0)
}

func TestBandwidthIdlePathSetsNoCeiling(t *testing.T) {
	d := newBWDriver()
	d.idle(2*time.Minute, 40)

	if d.b.haveCeiling {
		t.Fatalf("an idle path claimed a measured ceiling of %.0f kbps", d.b.ceilingKbps)
	}
	if got := d.b.limitKbps(d.now, d.c); got != 0 {
		t.Fatalf("limit = %.0f, want 0 (no opinion) for a path nothing has loaded", got)
	}
	// The whole point: no opinion has to mean permission, or a link that
	// has simply been quiet becomes ineligible for being quiet.
	if !d.b.view(d.now, d.c).canCarry(5000, d.c) {
		t.Fatal("a path with no estimate refused traffic; the gate must refuse on evidence, not ignorance")
	}
}

func TestBandwidthCleanLoadProvesFloorNotCeiling(t *testing.T) {
	d := newBWDriver()
	d.run(30*time.Second, 4000, 40, 0)

	if d.b.haveCeiling {
		t.Fatal("carrying 4 Mbps cleanly was read as having found a ceiling")
	}
	if d.b.provenKbps < 3500 {
		t.Fatalf("proven = %.0f kbps, want roughly the 4000 that flowed cleanly", d.b.provenKbps)
	}
	// Clean carriage says "at least this much" and nothing more, so it must
	// not start refusing traffic above what has happened to flow so far.
	if !d.b.view(d.now, d.c).canCarry(20000, d.c) {
		t.Fatal("a path with a proven floor but no observed ceiling refused traffic above it")
	}
}

func TestBandwidthOnsetSetsCeiling(t *testing.T) {
	d := newBWDriver()
	// A transfer ramping up the way a real one does: comfortable through
	// 4 Mbps, and at 8 the link starts to queue - 60 ms of round-trip rise
	// that the receive direction cannot account for.
	d.run(20*time.Second, 2000, 40, 0)
	d.run(20*time.Second, 4000, 40, 0)
	d.run(10*time.Second, 8000, 100, 0)

	if !d.b.haveCeiling {
		t.Fatal("queueing set in and no ceiling was recorded")
	}
	// Bounded below by the last rate carried clean and above by the rate
	// that caused the queueing. Anywhere in that band is a defensible
	// answer; outside it is not. The window straddling the ramp biases the
	// figure low, which is the direction to be wrong in.
	if d.b.ceilingKbps < 4000*bwSafety {
		t.Fatalf("ceiling = %.0f kbps, below the 4000 the path had already carried cleanly", d.b.ceilingKbps)
	}
	if d.b.ceilingKbps >= 8000 {
		t.Fatalf("ceiling = %.0f kbps, at or above the rate that caused the queueing", d.b.ceilingKbps)
	}
}

// A large download arriving on a path raises the round trip without this
// end having sent anything much. Read naively that looks like the send
// direction hitting a wall, and would cap a perfectly good uplink.
func TestBandwidthIgnoresReceiveDirectionQueueing(t *testing.T) {
	d := newBWDriver()
	d.run(30*time.Second, 2000, 40, 0)
	// Round trip up by 200 ms, all of it measured as receive-side queueing.
	d.run(20*time.Second, 2000, 240, 200)

	if d.b.haveCeiling {
		t.Fatalf("a saturated downlink capped the uplink at %.0f kbps", d.b.ceilingKbps)
	}
}

func TestBandwidthCeilingRevisedDownImmediately(t *testing.T) {
	d := newBWDriver()
	d.run(20*time.Second, 8000, 40, 0)
	d.run(10*time.Second, 8000, 100, 0) // onset at 8 Mbps
	high := d.b.ceilingKbps

	// The link degrades - a tower handover, weather on the dish - and now
	// queues even though the sender has backed off to a quarter of what it
	// was pushing.
	d.run(5*time.Second, 2000, 100, 0)

	if d.b.ceilingKbps >= high {
		t.Fatalf("ceiling stayed at %.0f kbps after queueing set in at 2000; a drop must be trusted at once", d.b.ceilingKbps)
	}
	if d.b.ceilingKbps > 2000 {
		t.Fatalf("ceiling = %.0f kbps, above the rate that has just been shown to queue", d.b.ceilingKbps)
	}
}

// A sender that keeps pushing into a link that has already collapsed sees
// its own offered rate stay high while nothing like it is getting through.
// Only the rate at the moment queueing began means anything; everything
// after it is the sender talking to itself.
func TestBandwidthOverrunDoesNotInflateCeiling(t *testing.T) {
	d := newBWDriver()
	d.run(20*time.Second, 2000, 40, 0)
	d.run(2*time.Second, 2000, 90, 0) // the wall, at about 2 Mbps

	atOnset := d.b.ceilingKbps
	if atOnset > 2000 {
		t.Fatalf("ceiling = %.0f kbps at onset, above the rate that caused it", atOnset)
	}

	// The transfer ramps regardless, as TCP does, and the buffer keeps
	// filling. None of this is evidence of more capacity.
	d.run(20*time.Second, 20000, 400, 0)

	if d.b.ceilingKbps > atOnset {
		t.Fatalf("ceiling rose to %.0f kbps from %.0f while the link was already congested",
			d.b.ceilingKbps, atOnset)
	}
}

func TestBandwidthCeilingLiftedByCleanCarriage(t *testing.T) {
	d := newBWDriver()
	d.run(20*time.Second, 2000, 40, 0)
	d.run(5*time.Second, 2000, 100, 0) // onset pins the ceiling near 1700
	low := d.b.ceilingKbps

	// Congestion clears and the path now carries 6 Mbps with an empty
	// buffer. The old number has been demonstrated wrong.
	d.run(20*time.Second, 6000, 40, 0)

	if d.b.ceilingKbps <= low {
		t.Fatalf("ceiling stuck at %.0f kbps while the path cleanly carried 6000", d.b.ceilingKbps)
	}
	if d.b.ceilingKbps > 6100 {
		t.Fatalf("ceiling = %.0f kbps, above anything that has actually flowed", d.b.ceilingKbps)
	}
}

// The question this design was written to answer: a burst, then an hour of
// nothing. The number must not decay, because idleness is not evidence that
// a link shrank. What decays is how much of it is leaned on.
func TestBandwidthIdleAgesConfidenceNotValue(t *testing.T) {
	d := newBWDriver()
	d.run(20*time.Second, 8000, 40, 0)
	d.run(10*time.Second, 8000, 100, 0)
	measured := d.b.ceilingKbps
	fresh := d.b.limitKbps(d.now, d.c)

	d.idle(time.Hour, 40)

	if d.b.ceilingKbps != measured {
		t.Fatalf("ceiling moved from %.0f to %.0f kbps over an idle hour; the value must not decay",
			measured, d.b.ceilingKbps)
	}
	stale := d.b.limitKbps(d.now, d.c)
	if stale >= fresh {
		t.Fatalf("limit stayed at %.0f kbps after an hour unconfirmed; confidence must age", stale)
	}
	if stale < measured*bwStaleFloor*0.99 {
		t.Fatalf("limit fell to %.0f kbps, below the %.0f floor; a stale estimate still beats no estimate",
			stale, measured*bwStaleFloor)
	}
	if !d.b.view(d.now, d.c).canCarry(measured*bwStaleFloor*0.5, d.c) {
		t.Fatal("an hour-old estimate refused traffic well inside even its discounted ceiling")
	}
}

// A path nobody has watched queue has no opinion, and no opinion has to mean
// permission. There used to be a configurable fallback here (bw_fallback_kbps)
// for a plan whose ceiling was known in advance; D-047 removed it as a knob
// nobody set. What must not change is the direction the unknown fails in:
// refusing on ignorance would make a link ineligible for having been quiet,
// which on a box whose links are quiet most of the time is most of them.
func TestUnmeasuredPathHasNoOpinionAndSoPermitsEverything(t *testing.T) {
	d := newBWDriver()
	d.idle(time.Minute, 600)

	v := d.b.view(d.now, d.c)
	if v.limitKbps != 0 {
		t.Fatalf("limit = %.0f, want 0 for a path never seen to queue", v.limitKbps)
	}
	if !v.canCarry(2000, d.c) {
		t.Fatal("an unmeasured path refused 2 Mbps; unknown must read as permission")
	}
	if v.haveCeiling {
		t.Fatal("an idle path claims a measured ceiling")
	}
}

func TestBandwidthHeadroomIsRequired(t *testing.T) {
	c := config.Defaults()
	c.BWHeadroomPercent = 20
	v := bwView{limitKbps: 1000, haveCeiling: true}

	if !v.canCarry(800, c) {
		t.Fatal("800 kbps refused on a 1000 kbps path with 20% headroom; 960 fits")
	}
	if v.canCarry(900, c) {
		t.Fatal("900 kbps accepted on a 1000 kbps path; with 20% headroom that is 1080")
	}
}

func TestBandwidthCountsWhatIsAlreadyFlowing(t *testing.T) {
	c := config.Defaults()
	c.BWHeadroomPercent = 0
	v := bwView{limitKbps: 1000, sendKbps: 700, haveCeiling: true}

	// A path already doing 700 has 300 left, not 1000. Duplicating a stream
	// onto a path busy carrying its own is exactly the mistake the estimate
	// exists to prevent.
	if !v.canCarry(200, c) {
		t.Fatal("200 refused on a path doing 700 of 1000")
	}
	if v.canCarry(400, c) {
		t.Fatal("400 accepted on a path already doing 700 of 1000")
	}
}

// A single spike of congestion - one busy report interval, then clear -
// must not collapse the estimate. Before the dwell (D-023 revision) the
// first queueing reading pinned the ceiling; now the congestion has to hold
// for BWOnsetDwell before it counts.
func TestBandwidthOnsetSpikeIgnored(t *testing.T) {
	d := newBWDriver()
	d.run(20*time.Second, 8000, 40, 0) // establish the floor at ~40 ms
	// A spike well shorter than the dwell, at a queue depth that would
	// otherwise set a ceiling immediately.
	spike := d.c.BWOnsetDwell() - 200*time.Millisecond
	d.run(spike, 8000, 120, 0)

	if d.b.haveCeiling {
		t.Fatalf("a %v spike set a ceiling of %.0f kbps; it should have been ridden out",
			spike, d.b.ceilingKbps)
	}

	// And it recovers cleanly: the streak is forgotten, not merely deferred.
	d.run(10*time.Second, 8000, 40, 0)
	if d.b.haveCeiling {
		t.Fatalf("a ceiling appeared after the spike cleared: %.0f kbps", d.b.ceilingKbps)
	}
}

// Congestion that persists past the dwell does set the ceiling, and at the
// rate latched when the onset began - not whatever was in flight once the
// buffer had been filling for a second.
func TestBandwidthSustainedOnsetCommitsAtOnsetRate(t *testing.T) {
	d := newBWDriver()
	d.run(20*time.Second, 2000, 40, 0) // floor, carrying ~2 Mbps cleanly
	// Onset held well past the dwell.
	d.run(d.c.BWOnsetDwell()+3*time.Second, 2000, 120, 0)

	if !d.b.haveCeiling {
		t.Fatal("sustained congestion past the dwell set no ceiling")
	}
	// The onset rate was ~2 Mbps, so the ceiling is that less the margin,
	// not something read mid-congestion.
	if d.b.ceilingKbps > 2000 {
		t.Fatalf("ceiling = %.0f kbps, above the onset rate", d.b.ceilingKbps)
	}
	if d.b.ceilingKbps < 1000 {
		t.Fatalf("ceiling = %.0f kbps, far below the ~1700 the onset rate implies", d.b.ceilingKbps)
	}
}

// runWithPeer is run() with a peer report in hand, so the delivered-rate
// discount of D-047 has something to work from.
func (d *bwDriver) runWithPeer(dur time.Duration, kbps, rttMs, downQueueMs, lossPercent float64) {
	const tick = 200 * time.Millisecond
	tx := peerView{valid: true, loss: lossPercent, at: d.now}
	for end := d.now + dur; d.now < end; {
		d.b.noteSent(int(kbps * 1000 / 8 * tick.Seconds()))
		d.now += tick
		tx.at = d.now
		d.b.observe(d.now, rttMs, downQueueMs, tx, d.c)
	}
}

// The Starlink case from D-046, at the estimator rather than the scheduler.
// A path given 40 Mbps that delivers a third of it has not proved it can
// carry 40 Mbps, and recording that it did is how a failing link keeps
// looking like the roomiest one on the box.
func TestProvenFloorCountsWhatArrivedNotWhatWasOffered(t *testing.T) {
	clean := newBWDriver()
	clean.runWithPeer(20*time.Second, 40_000, 40, 0, 0)

	lossy := newBWDriver()
	lossy.runWithPeer(20*time.Second, 40_000, 40, 0, 66)

	if clean.b.provenKbps < 30_000 {
		t.Fatalf("clean path proved only %.0f kbps of a 40 Mbps offer", clean.b.provenKbps)
	}
	if lossy.b.provenKbps >= clean.b.provenKbps {
		t.Errorf("a path losing 66%% proved %.0f kbps against the clean path's %.0f; "+
			"the floor must count arrivals, not departures",
			lossy.b.provenKbps, clean.b.provenKbps)
	}
	// A third of 40 Mbps, give or take the sampling window.
	if got := lossy.b.provenKbps; got < 10_000 || got > 20_000 {
		t.Errorf("lossy path proved %.0f kbps, want roughly the 13.6 Mbps that landed", got)
	}
}

// No report is not evidence of loss. An unreported path must be measured the
// way it always was, or every quiet link would be understated.
func TestProvenFloorIsUndiscountedWithoutAReport(t *testing.T) {
	d := newBWDriver()
	d.run(20*time.Second, 8_000, 40, 0)

	if d.b.provenKbps < 6_000 {
		t.Errorf("proven = %.0f kbps with no peer report, want roughly the 8 Mbps offered",
			d.b.provenKbps)
	}
}

// Driving out of a cell sector does not make the old ceiling less certain, it
// makes it wrong. The ageing curve holds a quiet link's estimate on purpose;
// this is the other case, where the link underneath has been replaced.
func TestCeilingIsDiscardedWhenTheRouteMoves(t *testing.T) {
	d := newBWDriver()
	// Fill the link at a 40 ms floor until a ceiling is recorded.
	d.run(10*time.Second, 8_000, 40, 0)
	d.run(10*time.Second, 8_000, 140, 0)
	if !d.b.haveCeiling {
		t.Fatal("no ceiling recorded; the test needs one to discard")
	}
	measured := d.b.ceilingKbps

	// The route changes: the floor moves from 40 ms to 400 ms.
	d.run(12*time.Minute, 12, 400, 0)

	if d.b.haveCeiling {
		t.Errorf("ceiling of %.0f kbps survived the floor moving 40ms -> 400ms; "+
			"it was measured on a link that is no longer there", measured)
	}
	if d.b.provenKbps != 0 {
		t.Errorf("proven floor %.0f kbps survived the route change too", d.b.provenKbps)
	}
}

// The reset must not fire on ordinary variation, or it would throw away every
// estimate the moment a link jittered.
func TestCeilingSurvivesOrdinaryDelayVariation(t *testing.T) {
	d := newBWDriver()
	d.run(10*time.Second, 8_000, 40, 0)
	d.run(10*time.Second, 8_000, 140, 0)
	if !d.b.haveCeiling {
		t.Fatal("no ceiling recorded")
	}

	d.run(2*time.Minute, 12, 55, 0) // well inside bwRegimeFactor

	if !d.b.haveCeiling {
		t.Error("a 40ms -> 55ms wobble discarded the ceiling; only a moved route should")
	}
}
