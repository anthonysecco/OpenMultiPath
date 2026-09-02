package protocol

import (
	"errors"
	"math"
	"reflect"
	"testing"
)

func TestRoundTripWithoutEcho(t *testing.T) {
	in := Header{
		Type:      TypeData,
		Class:     ClassRealtime,
		PathID:    3,
		GlobalSeq: 123456,
		PathSeq:   789,
		SendTS:    0xDEADBEEF,
	}
	payload := []byte("wireguard packet bytes")

	wire := append(in.AppendTo(nil, Version, nil), payload...)
	if len(wire) != BaseLen+len(payload) {
		t.Fatalf("encoded length = %d, want %d", len(wire), BaseLen+len(payload))
	}

	out, rest, _, err := Parse(wire, nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", out, in)
	}
	if string(rest) != string(payload) {
		t.Errorf("payload = %q, want %q", rest, payload)
	}
}

func TestRoundTripWithEcho(t *testing.T) {
	in := Header{
		Type:      TypeData,
		Class:     ClassBulk,
		PathID:    1,
		GlobalSeq: math.MaxUint32,
		PathSeq:   42,
		SendTS:    1000,
		Echo: []EchoEntry{
			{PathID: 1, TS: 900, Delay: 250, MaxSeen: 1472},
			{PathID: 2, TS: 880, Delay: 17000, MaxSeen: 0},
		},
	}
	payload := []byte{0x01, 0x02, 0x03}

	wire := append(in.AppendTo(nil, Version, nil), payload...)
	want := BaseLen + 1 + 2*EchoEntryLen + len(payload)
	if len(wire) != want {
		t.Fatalf("encoded length = %d, want %d", len(wire), want)
	}

	out, rest, _, err := Parse(wire, nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", out, in)
	}
	if string(rest) != string(payload) {
		t.Errorf("payload = %q, want %q", rest, payload)
	}
}

// A packet cut short anywhere must be reported, not silently parsed into
// garbage - these arrive off the open internet.
func TestParseTruncated(t *testing.T) {
	full := (&Header{
		PathID: 1,
		SendTS: 5,
		Echo:   []EchoEntry{{PathID: 1, TS: 2, Delay: 3}},
	}).AppendTo(nil, Version, nil)

	for n := 0; n < len(full); n++ {
		if _, _, _, err := Parse(full[:n], nil); !errors.Is(err, ErrShort) {
			t.Errorf("Parse(%d bytes) error = %v, want ErrShort", n, err)
		}
	}
}

// A claimed entry count is not a promise; these packets arrive off the
// open internet.
func TestParseRejectsImplausibleEchoCount(t *testing.T) {
	wire := (&Header{
		PathID: 1,
		Echo:   []EchoEntry{{PathID: 1}},
	}).AppendTo(nil, Version, nil)
	wire[BaseLen] = MaxEchoEntries + 1

	if _, _, _, err := Parse(wire, nil); !errors.Is(err, ErrMalformed) {
		t.Errorf("error = %v, want ErrMalformed", err)
	}
}

func TestParseRejectsOtherVersion(t *testing.T) {
	wire := (&Header{PathID: 1}).AppendTo(nil, Version, nil)
	wire[0] = (Version + 1) << 4

	if _, _, _, err := Parse(wire, nil); !errors.Is(err, ErrVersion) {
		t.Errorf("error = %v, want ErrVersion", err)
	}
}

// The echo flag is what tells the parser an echo block follows, so an
// empty echo list must not set it.
func TestEmptyEchoOmitsBlock(t *testing.T) {
	wire := (&Header{PathID: 1, Echo: []EchoEntry{}}).AppendTo(nil, Version, nil)
	if len(wire) != BaseLen {
		t.Fatalf("encoded length = %d, want %d", len(wire), BaseLen)
	}
	out, _, _, err := Parse(wire, nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(out.Echo) != 0 {
		t.Errorf("Echo = %+v, want empty", out.Echo)
	}
}

func TestSeqAfterWrapsCorrectly(t *testing.T) {
	tests := []struct {
		name string
		a, b uint32
		want bool
	}{
		{"strictly after", 11, 10, true},
		{"equal", 10, 10, false},
		{"strictly before", 9, 10, false},
		{"after, across wrap", 2, math.MaxUint32 - 2, true},
		{"before, across wrap", math.MaxUint32 - 2, 2, false},
	}
	for _, tt := range tests {
		if got := SeqAfter(tt.a, tt.b); got != tt.want {
			t.Errorf("%s: SeqAfter(%d, %d) = %v, want %v", tt.name, tt.a, tt.b, got, tt.want)
		}
	}
}

func TestMicrosSinceWrapsCorrectly(t *testing.T) {
	tests := []struct {
		name           string
		later, earlier uint32
		want           uint32
	}{
		{"simple", 5000, 1000, 4000},
		{"zero", 77, 77, 0},
		{"across wrap", 10, math.MaxUint32 - 9, 20},
	}
	for _, tt := range tests {
		if got := MicrosSince(tt.later, tt.earlier); got != tt.want {
			t.Errorf("%s: MicrosSince(%d, %d) = %d, want %d", tt.name, tt.later, tt.earlier, got, tt.want)
		}
	}
}

func TestRoundTripWithReports(t *testing.T) {
	in := Header{
		Type:   TypeReport,
		PathID: 2,
		SendTS: 4242,
		Reports: []ReportEntry{
			{PathID: 0, SpreadTenthMs: 91, QueueTenthMs: 12, JitterTenthMs: 7, LossPerMille: 25, BurstTenths: 14},
			{PathID: 1, SpreadTenthMs: 3, QueueTenthMs: 0, JitterTenthMs: 1, LossPerMille: 0, BurstTenths: 10},
		},
	}

	wire := in.AppendTo(nil, Version, nil)
	want := BaseLen + 1 + 2*ReportEntryLen
	if len(wire) != want {
		t.Fatalf("encoded length = %d, want %d", len(wire), want)
	}
	out, _, ver, err := Parse(wire, nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if ver != Version {
		t.Errorf("version = %d, want %d", ver, Version)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", out, in)
	}
}

// Version 1 has nowhere to put reports or a tag. Encoding for a version 1
// peer must drop them rather than emit something it cannot parse - the
// measurements are an optimisation, its packets are not.
func TestVersionOneDropsWhatItCannotCarry(t *testing.T) {
	in := Header{
		Type:    TypeReport,
		PathID:  1,
		Reports: []ReportEntry{{PathID: 0, SpreadTenthMs: 5}},
	}
	wire := in.AppendTo(nil, 1, []byte("a shared secret"))
	if len(wire) != BaseLen {
		t.Fatalf("encoded length = %d, want a bare %d byte header", len(wire), BaseLen)
	}
	if got := wire[0] >> 4; got != 1 {
		t.Errorf("encoded as version %d, want 1", got)
	}
	out, _, _, err := Parse(wire, nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(out.Reports) != 0 {
		t.Errorf("Reports = %+v, want none", out.Reports)
	}
}

// An old build must still be able to read what a new one sends it, and the
// other way round, or an upgrade becomes a flag day on a vehicle.
func TestVersionsInteroperate(t *testing.T) {
	for _, v := range []uint8{1, Version} {
		wire := (&Header{Type: TypeData, PathID: 1, GlobalSeq: 7, SendTS: 9}).AppendTo(nil, v, nil)
		out, _, _, err := Parse(wire, nil)
		if err != nil {
			t.Fatalf("version %d: Parse: %v", v, err)
		}
		if out.GlobalSeq != 7 || out.PathID != 1 {
			t.Errorf("version %d: header did not survive: %+v", v, out)
		}
	}
}

// Negotiation has to be able to start. Both ends begin by emitting the
// oldest version, so if the only evidence of capability were an actual
// version 2 packet, neither would ever send one and the upgrade would never
// happen. It deadlocked exactly that way on the vehicle before the
// capability flag existed.
func TestCapabilityIsAdvertisedOnOldPackets(t *testing.T) {
	wire := (&Header{Type: TypeData, PathID: 1}).AppendTo(nil, 1, nil)

	if got := wire[0] >> 4; got != 1 {
		t.Fatalf("encoded as version %d, want 1", got)
	}
	_, _, negotiated, err := Parse(wire, nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if negotiated != Version {
		t.Errorf("negotiated = %d, want %d: a version 1 packet from a new build must still advertise", negotiated, Version)
	}
}

// And a genuinely old peer, which sets no such flag, must keep getting
// version 1. This is the packet an un-upgraded vehicle sends.
func TestLegacyPeerStaysOnVersionOne(t *testing.T) {
	wire := (&Header{Type: TypeData, PathID: 1}).AppendTo(nil, 1, nil)
	wire[1] &^= flagCapable // as an old build would have left it

	_, _, negotiated, err := Parse(wire, nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if negotiated != 1 {
		t.Errorf("negotiated = %d for a legacy peer, want 1", negotiated)
	}
}

func TestAuthAcceptsAGoodTag(t *testing.T) {
	key := []byte("correct horse battery staple")
	wire := (&Header{Type: TypeData, PathID: 1, GlobalSeq: 5}).AppendTo(nil, Version, key)

	if _, _, _, err := Parse(wire, key); err != nil {
		t.Fatalf("a header we just signed did not verify: %v", err)
	}
}

// The point of the tag: a packet whose measurement metadata was altered in
// flight must not reach the scheduler.
func TestAuthRejectsTampering(t *testing.T) {
	key := []byte("correct horse battery staple")
	base := (&Header{
		Type:    TypeReport,
		PathID:  1,
		Reports: []ReportEntry{{PathID: 0, SpreadTenthMs: 10}},
	}).AppendTo(nil, Version, key)

	// Every byte, including the tag itself. The invariant is that no
	// alteration parses cleanly - not that each one fails the same way.
	// Structural checks necessarily run first, since the tag has to be
	// located before it can be verified, so flipping a length or a flag is
	// caught as malformed rather than as forged. Either way it is dropped,
	// which is the property that matters.
	for i := 0; i < len(base); i++ {
		wire := append([]byte(nil), base...)
		wire[i] ^= 0x01
		if _, _, _, err := Parse(wire, key); err == nil {
			t.Fatalf("flipping byte %d of %d parsed cleanly", i, len(base))
		}
	}

	// And the tag must be the reason for at least the payload-carrying
	// bytes, or it is not doing any work.
	wire := append([]byte(nil), base...)
	wire[BaseLen+2] ^= 0x01 // inside a report entry
	if _, _, _, err := Parse(wire, key); !errors.Is(err, ErrAuth) {
		t.Errorf("altering a report entry gave %v, want ErrAuth", err)
	}
}

// Stripping the tag must not be a way around it, or the check is decorative.
func TestAuthRejectsAStrippedTag(t *testing.T) {
	key := []byte("correct horse battery staple")
	wire := (&Header{Type: TypeData, PathID: 1}).AppendTo(nil, Version, nil)

	if _, _, _, err := Parse(wire, key); !errors.Is(err, ErrAuth) {
		t.Errorf("an untagged version 2 header parsed as %v, want ErrAuth", err)
	}
}

// A node with no key configured keeps working against one that has it, so
// turning authentication on is not itself a flag day.
func TestAuthIgnoredWhenNoKeyConfigured(t *testing.T) {
	wire := (&Header{Type: TypeData, PathID: 1, GlobalSeq: 3}).AppendTo(nil, Version, []byte("some key"))
	out, _, _, err := Parse(wire, nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if out.GlobalSeq != 3 {
		t.Errorf("GlobalSeq = %d, want 3", out.GlobalSeq)
	}
}
