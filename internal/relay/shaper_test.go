package relay

import (
	"sync"
	"testing"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

// shaperRig is one shaper writing into a slice, costing each packet exactly
// its length so rates are easy to reason about.
type shaperRig struct {
	sh    *pathShaper
	start time.Time

	mu      sync.Mutex
	written [][]byte
	bytes   int
}

func newShaperRig() *shaperRig {
	r := &shaperRig{start: time.Now()}
	r.sh = newPathShaper(
		func() time.Duration { return time.Since(r.start) },
		func(p *shapedPacket, buf []byte) []byte { return append(buf[:0], p.payload...) },
		func(pkt []byte) {
			r.mu.Lock()
			r.written = append(r.written, append([]byte(nil), pkt...))
			r.bytes += len(pkt)
			r.mu.Unlock()
		},
		func(n int) int { return n },
	)
	return r
}

func (r *shaperRig) sent() (packets, bytes int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.written), r.bytes
}

func (r *shaperRig) order() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]byte, len(r.written))
	for i, p := range r.written {
		out[i] = p[0]
	}
	return out
}

func pkt(tag byte, size int) []byte {
	b := make([]byte, size)
	b[0] = tag
	return b
}

// An unmeasured link is unshaped: every packet goes out at once, in order,
// with nothing queued and nothing dropped.
func TestUnshapedPathSendsEverythingAtOnce(t *testing.T) {
	r := newShaperRig()
	for i := 0; i < 1000; i++ {
		r.sh.send(protocol.ClassBulk, uint32(i), flowTag{}, pkt(byte(i), 1200))
	}
	if n, _ := r.sent(); n != 1000 {
		t.Fatalf("sent %d of 1000 immediately", n)
	}
	for i, b := range r.order() {
		if b != byte(i) {
			t.Fatalf("packet %d went out as %d", i, b)
		}
	}
	if r.sh.backlog() != 0 || r.sh.dropped.Load() != 0 {
		t.Errorf("backlog %d dropped %d on an unshaped path", r.sh.backlog(), r.sh.dropped.Load())
	}
	if !r.sh.hasRoom() {
		t.Error("an unshaped path reads as full")
	}
}

// A shaped path holds the rate: what has gone out after a while is the rate
// times the time, plus at most the bucket.
func TestShapedPathHoldsItsRate(t *testing.T) {
	r := newShaperRig()
	const kbps = 800 // 100 kB a second
	r.sh.setRate(kbps)
	for i := 0; i < 60; i++ {
		r.sh.send(protocol.ClassBulk, uint32(i), flowTag{}, pkt(byte(i), 1000))
	}
	time.Sleep(300 * time.Millisecond)
	_, bytes := r.sent()
	elapsed := time.Since(r.start).Seconds()
	allowed := kbps*125*elapsed + shaperMinBurstBytes + 1000
	if float64(bytes) > allowed {
		t.Errorf("sent %d bytes in %.2fs at %d kbps, want at most %.0f", bytes, elapsed, kbps, allowed)
	}
	if float64(bytes) < kbps*125*0.2 {
		t.Errorf("sent only %d bytes in %.2fs at %d kbps: the queue is not draining", bytes, elapsed, kbps)
	}
	if r.sh.hasRoom() {
		t.Error("a path with seconds of bulk queued reads as having room")
	}
}

// Real-time jumps the queue: queued behind a backlog of bulk, a call packet
// still goes out next.
func TestRealtimeDrainsAheadOfQueuedBulk(t *testing.T) {
	r := newShaperRig()
	r.sh.setRate(80) // 10 kB a second
	for i := 0; i < 30; i++ {
		r.sh.send(protocol.ClassBulk, uint32(i), flowTag{}, pkt('b', 1000))
	}
	r.sh.send(protocol.ClassRealtime, 99, flowTag{}, pkt('r', 200))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		order := r.order()
		for i, b := range order {
			if b != 'r' {
				continue
			}
			// Anything already on its way when the call packet arrived may go
			// first - the fast path's first packet and one popped by the drain
			// goroutine - but nothing queued behind it.
			if i > 3 {
				t.Fatalf("real-time went out after %d bulk packets: %q", i, order)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("real-time never went out: %q", r.order())
}

// Past the queue limit a packet is dropped rather than queued, which is how a
// sender learns the link is full.
func TestShaperDropsPastItsQueueLimit(t *testing.T) {
	r := newShaperRig()
	r.sh.setRate(8) // 1 kB a second, so the floor sets the limit
	for i := 0; i < 200; i++ {
		r.sh.send(protocol.ClassBulk, uint32(i), flowTag{}, pkt(0, 1000))
	}
	if r.sh.dropped.Load() == 0 {
		t.Error("nothing dropped with 200 kB offered to a 1 kB/s path")
	}
	if b := r.sh.backlog(); b > shaperMinQueueBytes {
		t.Errorf("backlog %d past the %d byte limit", b, shaperMinQueueBytes)
	}
}

// Clearing a path's measurement unshapes it, and what was queued goes out at
// once rather than waiting on a rate that no longer applies.
func TestClearingTheRateDrainsTheQueue(t *testing.T) {
	r := newShaperRig()
	r.sh.setRate(8)
	for i := 0; i < 20; i++ {
		r.sh.send(protocol.ClassBulk, uint32(i), flowTag{}, pkt(byte(i), 1000))
	}
	r.sh.setRate(0)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if n, _ := r.sent(); n == 20 {
			for i, b := range r.order() {
				if b != byte(i) {
					t.Fatalf("packet %d went out as %d", i, b)
				}
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	n, _ := r.sent()
	t.Fatalf("sent %d of 20 after clearing the rate", n)
}

// Measurement traffic is charged to the bucket, so data behind it waits its
// share rather than the link carrying both at full rate.
func TestControlTrafficIsCharged(t *testing.T) {
	r := newShaperRig()
	r.sh.setRate(80)
	r.sh.charge(5000) // more than the whole bucket
	r.sh.send(protocol.ClassBulk, 1, flowTag{}, pkt(0, 500))
	if n, _ := r.sent(); n != 0 {
		t.Error("data went out at once behind a charge larger than the bucket")
	}
	if r.sh.backlog() != 500 {
		t.Errorf("backlog %d, want the 500 byte packet queued", r.sh.backlog())
	}
}
