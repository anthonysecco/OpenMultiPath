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

	wire := append(in.AppendTo(nil), payload...)
	if len(wire) != BaseLen+len(payload) {
		t.Fatalf("encoded length = %d, want %d", len(wire), BaseLen+len(payload))
	}

	out, rest, err := Parse(wire)
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
			{PathID: 1, TS: 900, Delay: 250},
			{PathID: 2, TS: 880, Delay: 17000},
		},
	}
	payload := []byte{0x01, 0x02, 0x03}

	wire := append(in.AppendTo(nil), payload...)
	want := BaseLen + 1 + 2*EchoEntryLen + len(payload)
	if len(wire) != want {
		t.Fatalf("encoded length = %d, want %d", len(wire), want)
	}

	out, rest, err := Parse(wire)
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
	}).AppendTo(nil)

	for n := 0; n < len(full); n++ {
		if _, _, err := Parse(full[:n]); !errors.Is(err, ErrShort) {
			t.Errorf("Parse(%d bytes) error = %v, want ErrShort", n, err)
		}
	}
}

func TestParseRejectsOtherVersion(t *testing.T) {
	wire := (&Header{PathID: 1}).AppendTo(nil)
	wire[0] = (Version + 1) << 4

	if _, _, err := Parse(wire); !errors.Is(err, ErrVersion) {
		t.Errorf("error = %v, want ErrVersion", err)
	}
}

// The echo flag is what tells the parser an echo block follows, so an
// empty echo list must not set it.
func TestEmptyEchoOmitsBlock(t *testing.T) {
	wire := (&Header{PathID: 1, Echo: []EchoEntry{}}).AppendTo(nil)
	if len(wire) != BaseLen {
		t.Fatalf("encoded length = %d, want %d", len(wire), BaseLen)
	}
	out, _, err := Parse(wire)
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
