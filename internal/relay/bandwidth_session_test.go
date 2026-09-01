package relay

import (
	"testing"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
)

// The unit tests drive bwEstimate directly with a rate handed to it. This
// one checks the part they cannot: that the bytes counted are the bytes the
// session actually built, that the sampling happens where the evaluation
// pass happens, and that what comes out reaches the state file. Those are
// three separate places to have got the wiring wrong, and none of them
// would fail a test that fed the estimator its own numbers.
func TestSessionCountsWhatItActuallySends(t *testing.T) {
	s := newSession(config.NewHolder(config.Defaults()), "test", roleInitiator)
	s.registerPath(0)
	s.nameFor(0, "enp1s0")

	// 1200 byte payloads, the shape of tunnelled traffic rather than of a
	// synthetic benchmark.
	payload := make([]byte, 1200)
	buf := make([]byte, 0, bufSize+maxHeaderLen)

	// The first sample only starts the window; a rate needs an interval to
	// be measured over, and dividing whatever had piled up before the first
	// look by a window that had not started yet is how a daemon reports a
	// gigabit on its first tick.
	s.metrics(s.elapsed())

	const packets = 400
	var wire int
	for i := 0; i < packets; i++ {
		out := s.stamp(0, s.nextGlobalSeq(), payload, buf)
		wire += len(out) + ipUDPOverhead
	}

	time.Sleep(bwRateWindow + 100*time.Millisecond)
	m := s.metrics(s.elapsed())

	if len(m) != 1 {
		t.Fatalf("got %d paths, want 1", len(m))
	}
	got := m[0].bw.sendKbps
	if got <= 0 {
		t.Fatal("nothing was counted for a path that carried 400 packets")
	}

	// Everything went out inside one window, so the reported rate should be
	// those bytes over roughly that window. Generous bounds: the point is
	// that the figure is built from the real packet sizes and is not out by
	// an order of magnitude, not that a sleep in a test is precise.
	want := float64(wire) * 8 / 1000 / (bwRateWindow + 100*time.Millisecond).Seconds()
	if got < want*0.5 || got > want*2 {
		t.Errorf("send rate = %.0f kbps, want roughly %.0f from %d wire bytes", got, want, wire)
	}

	// And it has to survive the trip into the state file, which is what the
	// web interface and the history log both read.
	snap := s.snapshot(1400)
	if len(snap.Paths) != 1 {
		t.Fatalf("snapshot has %d paths, want 1", len(snap.Paths))
	}
	p := snap.Paths[0]
	if p.SendKbps <= 0 {
		t.Error("state file reports no send rate for a path that carried traffic")
	}
	if p.CeilingKnown {
		t.Error("state file claims a measured ceiling on a path that never queued")
	}
	if p.CeilingAgeSeconds != -1 {
		t.Errorf("ceiling age = %.1f, want -1 for a path with no round-trip measurements",
			p.CeilingAgeSeconds)
	}
}
