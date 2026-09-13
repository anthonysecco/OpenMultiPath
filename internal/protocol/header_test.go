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
		HasFlow:   true, // version 3 bulk data carries the flow sequence
		Echo: []EchoEntry{
			{PathID: 1, TS: 900, Delay: 250, MaxSeen: 1472},
			{PathID: 2, TS: 880, Delay: 17000, MaxSeen: 0},
		},
	}
	payload := []byte{0x01, 0x02, 0x03}

	wire := append(in.AppendTo(nil, Version, nil), payload...)
	want := BaseLen + FlowSeqLen + 1 + 2*EchoEntryLen + len(payload)
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
	want := BaseLen + 1 + 2*ReportEntryLenV3
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
	wire[1] &^= flagCapable | flagCapableV3 | flagCapableV4 // as an old build would have left it

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

// The upgrade to version 3 must not repeat the mistake the capability bit
// was read with before it: a version 2 peer advertises that it can read
// version 2, and a version 3 build must hear exactly that and no more.
// Emitting version 3 at it would have every packet rejected mid-upgrade.
func TestVersionTwoPeerIsNotSentVersionThree(t *testing.T) {
	wire := (&Header{Type: TypeData, PathID: 1}).AppendTo(nil, 2, nil)
	wire[1] &^= flagCapableV3 | flagCapableV4 // what a version 2 build leaves clear

	_, _, negotiated, err := Parse(wire, nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if negotiated != 2 {
		t.Errorf("negotiated = %d with a version 2 peer, want 2", negotiated)
	}
}

// And the other half: two version 3 builds find each other even while both
// are still emitting an older version, which is how every session starts.
func TestVersionThreeIsNegotiatedFromAnOlderPacket(t *testing.T) {
	for _, v := range []uint8{1, 2} {
		wire := (&Header{Type: TypeData, PathID: 1}).AppendTo(nil, v, nil)
		wire[1] &^= flagCapableV4 // what a version 3 build leaves clear
		_, _, negotiated, err := Parse(wire, nil)
		if err != nil {
			t.Fatalf("version %d: Parse: %v", v, err)
		}
		if negotiated != 3 {
			t.Errorf("version %d packet from a version 3 build negotiated %d, want 3", v, negotiated)
		}
	}
}

func TestFlowSequenceRoundTrip(t *testing.T) {
	in := Header{
		Type:       TypeData,
		Class:      ClassBulk,
		PathID:     1,
		GlobalSeq:  99,
		FlowBucket: FlowBuckets - 1,
		FlowSeq:    FlowSeqMask,
		HasFlow:    true,
		Echo:       []EchoEntry{{PathID: 0, TS: 5, Delay: 6, MaxSeen: 1400}},
	}
	payload := []byte("inner packet")
	wire := append(in.AppendTo(nil, 3, nil), payload...)
	if want := BaseLen + FlowSeqLen + 1 + EchoEntryLen + len(payload); len(wire) != want {
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

// The field is on version 3 bulk data and nowhere else. A version 2 peer
// cannot parse it, and real-time, transactional and control packets are
// never resequenced, so carrying it on them would be bytes for nothing.
func TestFlowSequenceOnlyOnVersionThreeBulkData(t *testing.T) {
	cases := []struct {
		name    string
		version uint8
		typ     uint8
		class   uint8
		want    bool
	}{
		{"v3 bulk data", 3, TypeData, ClassBulk, true},
		{"v2 bulk data", 2, TypeData, ClassBulk, false},
		{"v3 real-time data", 3, TypeData, ClassRealtime, false},
		{"v3 transactional data", 3, TypeData, ClassTransactional, false},
		{"v3 unclassified data", 3, TypeData, ClassUnknown, false},
		{"v3 bulk-classed report", 3, TypeReport, ClassBulk, false},
	}
	for _, tc := range cases {
		h := Header{Type: tc.typ, Class: tc.class, PathID: 1, FlowBucket: 7, FlowSeq: 42}
		wire := h.AppendTo(nil, tc.version, nil)
		grew := len(wire) == BaseLen+FlowSeqLen
		if grew != tc.want {
			t.Errorf("%s: encoded %d bytes, flow field present = %v, want %v", tc.name, len(wire), grew, tc.want)
		}
		out, _, _, err := Parse(wire, nil)
		if err != nil {
			t.Fatalf("%s: Parse: %v", tc.name, err)
		}
		if out.HasFlow != tc.want {
			t.Errorf("%s: HasFlow = %v, want %v", tc.name, out.HasFlow, tc.want)
		}
	}
}

// The flow sequence steers the resequencer, so forging it must be as hard as
// forging anything else in the header.
func TestAuthCoversTheFlowSequence(t *testing.T) {
	key := []byte("correct horse battery staple")
	wire := (&Header{Type: TypeData, Class: ClassBulk, PathID: 1, FlowBucket: 3, FlowSeq: 9}).AppendTo(nil, 3, key)
	if _, _, _, err := Parse(wire, key); err != nil {
		t.Fatalf("untampered packet: %v", err)
	}
	wire[BaseLen+3] ^= 0x01 // low byte of the sequence
	if _, _, _, err := Parse(wire, key); !errors.Is(err, ErrAuth) {
		t.Errorf("altering the flow sequence gave %v, want ErrAuth", err)
	}
}

func TestVersionThreeReportsCarryTheFastFigures(t *testing.T) {
	in := Header{
		Type:   TypeReport,
		PathID: 0,
		Reports: []ReportEntry{
			{PathID: 1, QueueTenthMs: 400, StandingQueueTenthMs: 120, LossPerMille: 3, ShortLossPerMille: 40, BurstTenths: 10, RxKbpsBy16: 1250},
		},
	}
	out, _, _, err := Parse(in.AppendTo(nil, 3, nil), nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("v3 round trip mismatch:\n got %+v\nwant %+v", out, in)
	}

	wire := in.AppendTo(nil, 2, nil)
	if want := BaseLen + 1 + ReportEntryLen; len(wire) != want {
		t.Fatalf("v2 encoding is %d bytes, want %d: a version 2 peer cannot read the longer entry", len(wire), want)
	}
	out, _, _, err = Parse(wire, nil)
	if err != nil {
		t.Fatalf("v2 Parse: %v", err)
	}
	if out.Reports[0].QueueTenthMs != 400 || out.Reports[0].StandingQueueTenthMs != 0 {
		t.Errorf("v2 report = %+v, want the version 2 fields only", out.Reports[0])
	}
}

// The field that wraps every million packets.
func TestFlowSeqDiffWraps(t *testing.T) {
	cases := []struct {
		a, b uint32
		want int32
	}{
		{10, 7, 3},
		{7, 10, -3},
		{0, FlowSeqMask, 1},
		{FlowSeqMask, 0, -1},
		{5, FlowSeqMask - 4, 10},
	}
	for _, tc := range cases {
		if got := FlowSeqDiff(tc.a, tc.b); got != tc.want {
			t.Errorf("FlowSeqDiff(%d, %d) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// The tunnel MTU arithmetic in v0.2-design.md: a 1420 byte path less outer
// IP/UDP, this header at its largest and WireGuard leaves 1288.
func TestDataHeaderBudget(t *testing.T) {
	if MaxDataHeaderLen != 72 {
		t.Errorf("MaxDataHeaderLen = %d, want 72; the deployed -tun-mtu depends on it", MaxDataHeaderLen)
	}
	if got := 1420 - 28 - MaxDataHeaderLen - 32; got != 1288 {
		t.Errorf("tunnel MTU on a 1420 path = %d, want 1288", got)
	}
}
