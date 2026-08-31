package relay

import (
	"encoding/json"
	"testing"

	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

// The snapshot runs on a timer inside the daemon, so anything that panics
// in it takes the tunnel down rather than merely spoiling a page. It has
// to survive every state a path can be in, including the empty one.
func TestSnapshotOfAFreshSession(t *testing.T) {
	s := newTestSession()
	s.registerPath(0)
	s.nameFor(0, "enp1s0")

	snap := s.snapshot(1310)

	if len(snap.Paths) != 1 {
		t.Fatalf("got %d paths, want 1", len(snap.Paths))
	}
	p := snap.Paths[0]
	if p.Name != "enp1s0" {
		t.Errorf("name = %q, want enp1s0", p.Name)
	}
	if p.Alive {
		t.Error("a path that has never delivered anything is reported alive")
	}
	if p.LastSeenSeconds != -1 {
		t.Errorf("last seen = %v on a silent path, want -1 meaning never", p.LastSeenSeconds)
	}
	if !p.Thin {
		t.Error("a path with no samples is not flagged as thin")
	}
	if snap.TunnelMTU != 1310 {
		t.Errorf("tunnel mtu = %d, want 1310", snap.TunnelMTU)
	}
}

// Every bucket must be labelled, including the overflow one that has no
// boundary of its own. Getting this wrong panicked the daemon in a restart
// loop, since the snapshot runs on a timer.
func TestSnapshotLabelsEveryBurstBucket(t *testing.T) {
	s := newTestSession()
	s.registerPath(0)
	s.observe(&protocol.Header{PathID: 0, PathSeq: 0}, 100)

	// A run far longer than the largest named bucket lands in the
	// overflow.
	s.mu.Lock()
	s.paths[0].stats.observeLoss(500)
	s.paths[0].stats.observeDelivered()
	s.mu.Unlock()

	snap := s.snapshot(1310)
	bursts := snap.Paths[0].Bursts

	if len(bursts) != len(burstBuckets)+1 {
		t.Fatalf("got %d buckets, want %d", len(bursts), len(burstBuckets)+1)
	}
	for i, b := range bursts {
		if b.Label == "" {
			t.Errorf("bucket %d has no label", i)
		}
	}
	if got := bursts[len(burstBuckets)].Count; got != 1 {
		t.Errorf("overflow bucket count = %d, want 1", got)
	}
}

// The page is driven entirely by this JSON, so it has to encode.
func TestSnapshotEncodesToJSON(t *testing.T) {
	s := newTestSession()
	s.registerPath(0)
	s.observe(&protocol.Header{PathID: 0, PathSeq: 0, SendTS: 500}, 143)

	b, err := json.Marshal(s.snapshot(1310))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, key := range []string{"node", "role", "updated_unix", "paths", "aggregate", "config"} {
		if _, ok := back[key]; !ok {
			t.Errorf("encoded snapshot is missing %q", key)
		}
	}
}

// Loss is a share of everything that should have arrived, not of what did.
func TestAggregateLossCountsWhatNeverArrived(t *testing.T) {
	s := newTestSession()
	s.registerPath(0)
	s.observe(&protocol.Header{PathID: 0, PathSeq: 0}, 100)
	s.observe(&protocol.Header{PathID: 0, PathSeq: 3}, 100) // 1 and 2 lost

	snap := s.snapshot(0)
	// Two arrived, two did not: half of what should have arrived is lost.
	if got := snap.Aggregate.LossPercent; got != 50 {
		t.Errorf("aggregate loss = %v%%, want 50", got)
	}
	if got := snap.Aggregate.Received; got != 2 {
		t.Errorf("aggregate received = %d, want 2", got)
	}
	if got := snap.Aggregate.Lost; got != 2 {
		t.Errorf("aggregate lost = %d, want 2", got)
	}
}
