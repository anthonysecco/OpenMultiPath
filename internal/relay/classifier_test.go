package relay

import (
	"encoding/binary"
	"testing"

	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

// fakeEndpoint stands in for a local endpoint whose payloads are or are
// not plaintext, without needing a device to exist.
type fakeEndpoint struct{ plain bool }

func (f fakeEndpoint) readPayloads(string, func([]byte)) {}
func (f fakeEndpoint) write([]byte) error                { return nil }
func (f fakeEndpoint) describe() string                  { return "fake" }
func (f fakeEndpoint) plaintext() bool                   { return f.plain }
func (f fakeEndpoint) Close() error                      { return nil }

// stunOverUDP builds an inner packet a working classifier must call
// real-time on sight - a STUN binding request, which is how a WebRTC flow
// announces itself before any media (D-019).
func stunOverUDP() []byte {
	stun := make([]byte, 20)
	binary.BigEndian.PutUint16(stun[0:2], 0x0001)     // binding request
	binary.BigEndian.PutUint32(stun[4:8], 0x2112A442) // magic cookie
	return testUDPPacket("10.20.0.2", 51234, "142.250.1.1", 19302, stun)
}

// The gate that matters. Below WireGuard the payload is an encrypted blob,
// and a 5-tuple parser pointed at one does not fail - it finds
// plausible-looking addresses in random bytes. Classifying there would
// produce confident nonsense, and confident nonsense steers calls.
func TestNoClassificationOnCiphertext(t *testing.T) {
	clf := newFlowClassifier(fakeEndpoint{plain: false}, nil)

	if clf.enabled() {
		t.Error("classification reported enabled on a ciphertext endpoint")
	}
	// Hand it something that would classify real-time if it were looked at.
	if got := clf.classify(stunOverUDP()); got != protocol.ClassUnknown {
		t.Errorf("a ciphertext endpoint classified a payload as %d; it must not look inside at all", got)
	}
}

// And the other half: where payloads really are inner packets, step 7 runs.
func TestClassificationRunsOnPlaintext(t *testing.T) {
	clf := newFlowClassifier(fakeEndpoint{plain: true}, nil)

	if !clf.enabled() {
		t.Fatal("classification is not running on a plaintext endpoint")
	}
	if got := clf.classify(stunOverUDP()); got != protocol.ClassRealtime {
		t.Errorf("a STUN binding request classified as %d, want real-time", got)
	}
}

// The class has to survive the wire, or the far end schedules on nothing.
func TestClassIsCarriedInTheHeader(t *testing.T) {
	s := newSession(nil, "test", roleInitiator)
	s.registerPath(0)

	for _, class := range []uint8{protocol.ClassUnknown, protocol.ClassRealtime, protocol.ClassBulk} {
		out := s.stamp(0, s.nextGlobalSeq(), class, []byte("payload"), nil)
		h, _, _, err := protocol.Parse(out, nil)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if h.Class != class {
			t.Errorf("class %d went out and came back as %d", class, h.Class)
		}
	}
}

// One packet, one class, however many copies it takes to deliver. If the
// duplicate copies of a packet disagreed, the far end would see the same
// global sequence arrive under two classes and have no way to choose.
func TestEveryCopyOfAPacketCarriesOneClass(t *testing.T) {
	s := newSession(nil, "test", roleInitiator)
	s.registerPath(0)
	s.registerPath(1)

	seq := s.nextGlobalSeq()
	payload := []byte("audio frame")

	a, _, _, err := protocol.Parse(s.stamp(0, seq, protocol.ClassRealtime, payload, nil), nil)
	if err != nil {
		t.Fatalf("parse path 0: %v", err)
	}
	b, _, _, err := protocol.Parse(s.stamp(1, seq, protocol.ClassRealtime, payload, nil), nil)
	if err != nil {
		t.Fatalf("parse path 1: %v", err)
	}

	if a.GlobalSeq != b.GlobalSeq {
		t.Fatalf("copies carry different global sequences, %d and %d", a.GlobalSeq, b.GlobalSeq)
	}
	if a.Class != b.Class {
		t.Errorf("two copies of one packet went out as class %d and class %d", a.Class, b.Class)
	}
}

// Probes and reports carry no user traffic, so they must not be dressed up
// as classified - a real-time probe would be a lie the scheduler could act
// on.
func TestProbesAndReportsGoOutUnclassified(t *testing.T) {
	s := newSession(nil, "test", roleInitiator)
	s.registerPath(0)

	h, _, _, err := protocol.Parse(s.build(protocol.TypeProbe, 0, s.nextGlobalSeq(), nil, nil), nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if h.Class != protocol.ClassUnknown {
		t.Errorf("a probe went out as class %d, want unclassified", h.Class)
	}
}

// The counters are what make the classifier answerable from a campground:
// "saw no real-time traffic" and "was not classifying" otherwise look
// identical in the log.
func TestClassCountersRecordWhatWasDecided(t *testing.T) {
	s := newSession(nil, "test", roleInitiator)
	for i := 0; i < 5; i++ {
		s.noteClass(protocol.ClassRealtime)
	}
	for i := 0; i < 3; i++ {
		s.noteClass(protocol.ClassBulk)
	}
	s.noteClass(protocol.ClassUnknown)
	s.noteClass(200) // out of range; must not panic or corrupt a counter

	rt, bulk, unk := s.classTotals()
	if rt != 5 || bulk != 3 || unk != 1 {
		t.Errorf("counted realtime=%d bulk=%d unknown=%d, want 5/3/1", rt, bulk, unk)
	}
}
