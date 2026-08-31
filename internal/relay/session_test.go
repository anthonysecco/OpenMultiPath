package relay

import (
	"testing"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

// The point of the four-timestamp model is that the peer reports how long
// it sat on a packet, so its think time can be subtracted back out. Both
// sessions here are in the same process, so the true round trip is
// microseconds no matter how long the far end holds the packet.
func TestEchoMeasuresRoundTripExcludingPeerHoldTime(t *testing.T) {
	initiator := newSession()
	responder := newSession()

	// Age both sessions past the echo interval so feedback is attached.
	time.Sleep(2 * echoInterval)

	out := initiator.stamp(0, initiator.nextGlobalSeq(), []byte("payload"), nil)
	h, _, err := protocol.Parse(out)
	if err != nil {
		t.Fatalf("parse outbound: %v", err)
	}
	responder.observe(&h, len(out))

	// The far end sits on it before replying.
	const hold = 150 * time.Millisecond
	time.Sleep(hold)

	reply := responder.stamp(0, responder.nextGlobalSeq(), []byte("reply"), nil)
	rh, _, err := protocol.Parse(reply)
	if err != nil {
		t.Fatalf("parse reply: %v", err)
	}
	if len(rh.Echo) == 0 {
		t.Fatal("reply carried no echo block")
	}
	initiator.observe(&rh, len(reply))

	got := time.Duration(initiator.paths[0].rtt) * time.Microsecond
	if got > hold/2 {
		t.Errorf("rtt = %v, want well under the %v peer hold time; "+
			"hold time looks like it is not being subtracted", got, hold)
	}
}

func TestPerPathSequenceGapsCountAsLoss(t *testing.T) {
	s := newSession()
	recv := func(seq uint32) {
		s.observe(&protocol.Header{PathID: 1, PathSeq: seq}, 100)
	}

	recv(0)
	recv(1)
	recv(2)
	if got := s.paths[1].stats.lost; got != 0 {
		t.Errorf("lost = %d after a clean run, want 0", got)
	}

	recv(5) // 3 and 4 never showed up
	if got := s.paths[1].stats.lost; got != 2 {
		t.Errorf("lost = %d after a gap of two, want 2", got)
	}

	recv(6)
	if got := s.paths[1].stats.lost; got != 2 {
		t.Errorf("lost = %d after resuming in order, want it unchanged at 2", got)
	}
	if got := s.paths[1].stats.received; got != 5 {
		t.Errorf("received = %d, want 5", got)
	}
}

// Loss on one path must not be attributed to another. Keeping the counters
// separate is the whole reason there is a per-path sequence in addition to
// the global one.
func TestLossIsTrackedPerPath(t *testing.T) {
	s := newSession()
	s.observe(&protocol.Header{PathID: 0, PathSeq: 0}, 100)
	s.observe(&protocol.Header{PathID: 1, PathSeq: 0}, 100)
	s.observe(&protocol.Header{PathID: 0, PathSeq: 9}, 100)

	if got := s.paths[0].stats.lost; got != 8 {
		t.Errorf("path 0 lost = %d, want 8", got)
	}
	if got := s.paths[1].stats.lost; got != 0 {
		t.Errorf("path 1 lost = %d, want 0", got)
	}
}

// Every copy of a duplicated packet has to carry the same global sequence,
// since that is what identifies them as the same packet at the far end,
// while each path's own sequence advances independently.
func TestDuplicatedCopiesShareGlobalSequence(t *testing.T) {
	s := newSession()
	payload := []byte("packet")

	seq := s.nextGlobalSeq()
	first, _, err := protocol.Parse(s.stamp(0, seq, payload, nil))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	second, _, err := protocol.Parse(s.stamp(1, seq, payload, nil))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if first.GlobalSeq != second.GlobalSeq {
		t.Errorf("global sequences differ across copies: %d vs %d", first.GlobalSeq, second.GlobalSeq)
	}
	if first.PathID == second.PathID {
		t.Errorf("both copies claim path %d", first.PathID)
	}

	// A second packet on path 0 advances that path's own sequence.
	third, _, err := protocol.Parse(s.stamp(0, s.nextGlobalSeq(), payload, nil))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if third.PathSeq != first.PathSeq+1 {
		t.Errorf("path 0 sequence = %d, want %d", third.PathSeq, first.PathSeq+1)
	}
	if third.GlobalSeq == first.GlobalSeq {
		t.Error("distinct packets share a global sequence")
	}
}
