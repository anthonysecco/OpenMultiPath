package relay

import (
	"testing"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

// A probe is only meaningful if it is actually the size being tested, and
// padded rather than small: protocol.md warns that a 60 byte probe
// experiences different serialisation delay than a full-sized packet,
// enough to bias comparisons between paths.
func TestProbeIsPaddedToTheSizeUnderTest(t *testing.T) {
	s := newTestSession()
	s.registerPath(0)

	pkt := s.buildProbe(0, nil)
	if pkt == nil {
		t.Fatal("no probe produced for a fresh path")
	}
	if want := mtuLadder[0] - ipUDPOverhead; len(pkt) != want {
		t.Errorf("probe is %d bytes on the wire, want %d", len(pkt), want)
	}

	h, _, err := protocol.Parse(pkt)
	if err != nil {
		t.Fatalf("probe does not parse: %v", err)
	}
	if h.Type != protocol.TypeProbe {
		t.Errorf("probe type = %d, want %d", h.Type, protocol.TypeProbe)
	}
}

// The peer confirms a probe by reporting the largest packet it has seen,
// which answers the question directly instead of inferring it from a
// report that only ever names the most recent packet.
func TestProbeConfirmationAdvancesTheSearch(t *testing.T) {
	s := newTestSession()
	s.registerPath(0)

	pkt := s.buildProbe(0, nil)
	sent := len(pkt)

	s.observe(&protocol.Header{
		PathID: 0,
		Echo:   []protocol.EchoEntry{{PathID: 0, MaxSeen: uint16(sent)}},
	}, 100)

	if got := s.paths[0].mtu.confirmed; got != mtuLadder[0] {
		t.Fatalf("confirmed mtu = %d, want %d", got, mtuLadder[0])
	}

	// With the first rung confirmed, the search moves up.
	next := s.buildProbe(0, nil)
	if next == nil {
		t.Fatal("search stopped after confirming the first size")
	}
	if want := mtuLadder[1] - ipUDPOverhead; len(next) != want {
		t.Errorf("next probe is %d bytes, want %d", len(next), want)
	}
}

// A report that only mentions smaller packets says nothing about whether
// the probe arrived, and must not be taken as confirmation.
func TestSmallerReportDoesNotConfirmProbe(t *testing.T) {
	s := newTestSession()
	s.registerPath(0)
	s.buildProbe(0, nil)

	s.observe(&protocol.Header{
		PathID: 0,
		Echo:   []protocol.EchoEntry{{PathID: 0, MaxSeen: 200}},
	}, 200)

	if got := s.paths[0].mtu.confirmed; got != 0 {
		t.Errorf("confirmed mtu = %d on a smaller report, want 0", got)
	}
}

// A size that never comes back has to retire, or the search would keep
// re-sending packets the path has already shown it cannot carry.
func TestRepeatedlyUnconfirmedSizeRetires(t *testing.T) {
	s := newTestSession()
	s.registerPath(0)

	for i := 0; i < probeMisses; i++ {
		if pkt := s.buildProbe(0, nil); pkt == nil {
			t.Fatalf("attempt %d produced no probe", i)
		}
		// Age the outstanding probe past its timeout without any
		// confirming report.
		s.mu.Lock()
		s.paths[0].mtu.sentAt = s.elapsed() - probeTimeout
		s.mu.Unlock()
	}

	// The next call notices the final miss and gives up on this rung.
	s.buildProbe(0, nil)
	if got := s.paths[0].mtu.ceiling; got != mtuLadder[0] {
		t.Errorf("ceiling = %d, want the failed size %d", got, mtuLadder[0])
	}
	if pkt := s.buildProbe(0, nil); pkt != nil {
		t.Errorf("still probing at %d bytes after the size retired", len(pkt))
	}
}

// A packet sized for a large path cannot be moved onto a small one, so the
// tunnel has to be sized to the smallest path rather than the best.
func TestRecommendedMTUTakesTheSmallestPath(t *testing.T) {
	s := newTestSession()
	s.registerPath(0)
	s.registerPath(1)

	s.mu.Lock()
	s.paths[0].mtu.confirmed = 1500
	s.paths[1].mtu.confirmed = 1400
	s.mu.Unlock()

	want := 1400 - ipUDPOverhead - protocol.MaxHeaderLen - wireGuardOverhead
	if got := s.recommendedTunnelMTU(); got != want {
		t.Errorf("recommended mtu = %d, want %d from the smaller path", got, want)
	}
}

// A path too small to carry the floor is excluded rather than dragging the
// tunnel down with it. Clamping it up to the floor instead would recommend
// an MTU the path has already shown it cannot carry.
func TestUnusablePathIsExcludedNotClamped(t *testing.T) {
	s := newTestSession()
	s.registerPath(0)
	s.registerPath(1)

	s.mu.Lock()
	s.paths[0].mtu.confirmed = 1500
	s.paths[1].mtu.confirmed = minUsablePathMTU - 1
	s.paths[1].mtu.ceiling = minUsablePathMTU
	s.mu.Unlock()

	want := 1500 - ipUDPOverhead - protocol.MaxHeaderLen - wireGuardOverhead
	if got := s.recommendedTunnelMTU(); got != want {
		t.Errorf("recommended mtu = %d, want %d from the one usable path", got, want)
	}
	if got := s.recommendedTunnelMTU(); got < minTunnelMTU {
		t.Errorf("recommended mtu = %d, below the %d floor", got, minTunnelMTU)
	}

	s.mu.Lock()
	bad := s.unusablePathsLocked()
	s.mu.Unlock()
	if len(bad) != 1 || bad[0] != 1 {
		t.Errorf("unusable paths = %v, want just path 1", bad)
	}
}

// With nothing able to carry the floor there is no honest recommendation
// to make, and inventing one would be worse than admitting it.
func TestNoRecommendationWhenEveryPathIsTooSmall(t *testing.T) {
	s := newTestSession()
	s.registerPath(0)

	s.mu.Lock()
	s.paths[0].mtu.confirmed = 600
	s.mu.Unlock()

	if got := s.recommendedTunnelMTU(); got != 0 {
		t.Errorf("recommended mtu = %d, want 0 when no path can carry the floor", got)
	}
}

// The smallest rung probed must itself be able to carry the floor, or the
// search would spend its time confirming sizes that are of no use.
func TestLadderStartsAtAUsableSize(t *testing.T) {
	if mtuLadder[0] < minUsablePathMTU {
		t.Errorf("ladder starts at %d, below the %d needed to carry the floor",
			mtuLadder[0], minUsablePathMTU)
	}
	inner := mtuLadder[0] - ipUDPOverhead - protocol.MaxHeaderLen - wireGuardOverhead
	if inner < minTunnelMTU {
		t.Errorf("smallest rung yields a %d byte tunnel, below the %d floor", inner, minTunnelMTU)
	}
}

func TestRecommendedMTUUnknownUntilSomethingConfirms(t *testing.T) {
	s := newTestSession()
	s.registerPath(0)
	if got := s.recommendedTunnelMTU(); got != 0 {
		t.Errorf("recommended mtu = %d before anything confirmed, want 0", got)
	}
}

// Feedback rides on data whenever there is data, and only needs a packet
// of its own when the reverse direction has gone quiet.
func TestStandaloneReportsOnlyWhenIdle(t *testing.T) {
	s := newTestSession()
	s.registerPath(0)

	s.stamp(0, s.nextGlobalSeq(), []byte("data"), nil)
	if s.dueForReport() {
		t.Error("a standalone report is due immediately after sending data")
	}

	// Wind the last-sent reading back past the interval.
	s.mu.Lock()
	s.lastSent = s.elapsed() - 2*testEchoInterval
	s.mu.Unlock()

	if !s.dueForReport() {
		t.Error("no report due after the reverse direction went quiet")
	}

	report := s.buildReport(0, nil)
	h, payload, err := protocol.Parse(report)
	if err != nil {
		t.Fatalf("report does not parse: %v", err)
	}
	if h.Type != protocol.TypeReport {
		t.Errorf("report type = %d, want %d", h.Type, protocol.TypeReport)
	}
	if len(payload) != 0 {
		t.Errorf("report carries %d bytes of payload, want none", len(payload))
	}
	if s.dueForReport() {
		t.Error("still due for a report immediately after sending one")
	}
}

// Reports have to keep flowing on a path nothing has arrived on, since
// passive measurement is blind exactly there.
func TestReportsGoOutOnSilentPaths(t *testing.T) {
	s := newTestSession()
	s.registerPath(0)
	s.registerPath(1)

	sent := map[uint8]int{}
	done := make(chan struct{})
	go func() {
		s.mu.Lock()
		s.lastSent = s.elapsed() - 2*testEchoInterval
		s.mu.Unlock()

		for _, id := range []uint8{0, 1} {
			if pkt := s.buildReport(id, nil); len(pkt) > 0 {
				sent[id]++
			}
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out building reports")
	}

	for _, id := range []uint8{0, 1} {
		if sent[id] != 1 {
			t.Errorf("path %d got %d reports, want 1", id, sent[id])
		}
	}
}
