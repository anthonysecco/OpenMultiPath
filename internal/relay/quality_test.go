package relay

import "testing"

// The claim that justifies collecting a burst distribution at all. If the
// model cannot tell these two paths apart then the burst buckets are
// decoration and a plain loss rate would have done.
func TestClusteredLossScoresWorseThanScatteredLoss(t *testing.T) {
	const delay, loss = 80.0, 1.0

	scattered := rFactor(delay, loss, 1)
	clustered := rFactor(delay, loss, 20)

	if clustered >= scattered {
		t.Errorf("1%% loss in runs of twenty scored %.1f, no worse than the same rate scattered at %.1f;"+
			" concealment covers an isolated gap and cannot cover 400 ms of silence", clustered, scattered)
	}
}

// G.114's knee: conversation is unimpaired until about 150 ms one way and
// degrades quickly after. Nothing should be charged for delay below it.
func TestDelayIsFreeUntilItIsNot(t *testing.T) {
	if got := delayImpairment(80); got != 0 {
		t.Errorf("80 ms of one-way delay was charged %.1f R points, want none", got)
	}
	if got := delayImpairment(100); got != 0 {
		t.Errorf("100 ms was charged %.1f R points, want none", got)
	}

	near, far := delayImpairment(200), delayImpairment(400)
	if near <= 0 {
		t.Errorf("200 ms was charged %.1f R points, want a real penalty", near)
	}
	if far <= near {
		t.Errorf("400 ms (%.1f) was charged no more than 200 ms (%.1f)", far, near)
	}
}

// protocol.md's worked example, which is the whole reason tail latency is
// scored rather than the mean: "a 60 ms path with 5 ms jitter beats a 40 ms
// path with 40 ms jitter, because the jitter buffer sizes to the tail."
func TestSteadySlowPathBeatsFastJitteryPath(t *testing.T) {
	const base = 50.0

	steady := rFactor(effectiveDelayMs(120, 5, base), 0, 1)  // 60 ms one way, tight
	jittery := rFactor(effectiveDelayMs(80, 40, base), 0, 1) // 40 ms one way, ragged

	if steady <= jittery {
		t.Errorf("steady 60 ms path scored %.1f, no better than the jittery 40 ms path at %.1f", steady, jittery)
	}
}

// A clean path must outscore a lossy one at the same delay, or the ranking
// is meaningless.
func TestLossCostsQuality(t *testing.T) {
	clean := rFactor(80, 0, 1)
	lossy := rFactor(80, 5, 1)
	if lossy >= clean {
		t.Errorf("5%% loss scored %.1f against a clean path's %.1f", lossy, clean)
	}
}

// The scale has to stay inside its own bounds however absurd the input,
// because these figures end up on a page someone reads at 2am.
func TestScoresStayOnTheScale(t *testing.T) {
	for _, tc := range []struct{ delay, loss, burst float64 }{
		{0, 0, 1}, {10_000, 0, 1}, {80, 100, 50}, {0, 100, 1}, {5_000, 60, 30},
	} {
		r := rFactor(tc.delay, tc.loss, tc.burst)
		if r < 0 || r > 100 {
			t.Errorf("rFactor(%v, %v, %v) = %.1f, outside 0-100", tc.delay, tc.loss, tc.burst, r)
		}
		if m := mosFrom(r); m < 1 || m > 4.5 {
			t.Errorf("mosFrom(%.1f) = %.2f, outside 1-4.5", r, m)
		}
	}
}

// MOS is only ever a restatement of R, so it must not reorder anything.
func TestMOSAgreesWithRFactorOrdering(t *testing.T) {
	prev := mosFrom(0)
	for r := 5.0; r <= 100; r += 5 {
		got := mosFrom(r)
		if got < prev {
			t.Errorf("MOS fell from %.3f to %.3f as R rose to %.0f", prev, got, r)
		}
		prev = got
	}
}

// A path with no loss should be charged nothing for loss, whatever the
// burst ratio claims.
func TestNoLossCostsNothing(t *testing.T) {
	if got := lossImpairment(0, 10); got != ieCodec {
		t.Errorf("a clean path was charged %.1f, want the codec's own %.1f", got, ieCodec)
	}
}
