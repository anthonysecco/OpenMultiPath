package protocol

import (
	"errors"
	"testing"
)

func TestLinkSpeedRoundTrip(t *testing.T) {
	in := []LinkSpeed{
		{PathID: 1, UpKbps: 3_000, DownKbps: 0, MeasuredUnix: 1_790_000_000},
		{PathID: 0, UpKbps: 12_000, DownKbps: 95_000, MeasuredUnix: 1_790_000_100},
	}
	b := AppendLinkSpeed(nil, in)
	digest, out, err := ParseLinkSpeed(b)
	if err != nil {
		t.Fatalf("ParseLinkSpeed: %v", err)
	}
	if digest != LinkSpeedDigest(in) {
		t.Errorf("digest %08x, want %08x", digest, LinkSpeedDigest(in))
	}
	if len(out) != 2 || out[0] != in[1] || out[1] != in[0] {
		t.Errorf("decoded %+v, want %+v sorted by path id", out, in)
	}
}

// The digest is what tells the vehicle home already holds a set, so the same
// contents in any order must produce it, and any change must not.
func TestLinkSpeedDigestIsByContent(t *testing.T) {
	a := []LinkSpeed{{PathID: 0, UpKbps: 1}, {PathID: 1, DownKbps: 2}}
	b := []LinkSpeed{{PathID: 1, DownKbps: 2}, {PathID: 0, UpKbps: 1}}
	if LinkSpeedDigest(a) != LinkSpeedDigest(b) {
		t.Error("the same set in another order digests differently")
	}
	c := []LinkSpeed{{PathID: 0, UpKbps: 1}, {PathID: 1, DownKbps: 3}}
	if LinkSpeedDigest(a) == LinkSpeedDigest(c) {
		t.Error("a changed speed kept the same digest")
	}
	if LinkSpeedDigest(nil) == LinkSpeedDigest(a) {
		t.Error("the empty set digests the same as a real one")
	}
}

func TestLinkSpeedRejectsCorruption(t *testing.T) {
	b := AppendLinkSpeed(nil, []LinkSpeed{{PathID: 0, UpKbps: 5000}})
	b[6] ^= 0xff // inside the entry, not the digest
	if _, _, err := ParseLinkSpeed(b); !errors.Is(err, ErrMalformed) {
		t.Errorf("corrupt entry: err = %v, want ErrMalformed", err)
	}
	if _, _, err := ParseLinkSpeed(b[:7]); !errors.Is(err, ErrShort) {
		t.Errorf("truncated: err = %v, want ErrShort", err)
	}
	huge := []byte{0, 0, 0, 0, MaxLinkSpeedEntries + 1}
	if _, _, err := ParseLinkSpeed(huge); !errors.Is(err, ErrMalformed) {
		t.Errorf("oversized count: err = %v, want ErrMalformed", err)
	}
}

func TestLinkSpeedAckRoundTrip(t *testing.T) {
	got, err := ParseLinkSpeedAck(AppendLinkSpeedAck(nil, 0xdeadbeef))
	if err != nil || got != 0xdeadbeef {
		t.Errorf("ack = %08x, %v", got, err)
	}
}

// A version 4 build hearing a version 3 peer, which leaves bit 7 clear, must
// settle on 3 - sending link speeds at it would go unanswered forever. Two
// version 4 builds find 4 from any older packet.
func TestVersionThreePeerIsNotSentVersionFour(t *testing.T) {
	wire := (&Header{Type: TypeData, PathID: 1}).AppendTo(nil, 3, nil)
	wire[1] &^= flagCapableV4
	_, _, negotiated, err := Parse(wire, nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if negotiated != 3 {
		t.Errorf("negotiated = %d with a version 3 peer, want 3", negotiated)
	}

	wire = (&Header{Type: TypeData, PathID: 1}).AppendTo(nil, 3, nil)
	if _, _, negotiated, _ = Parse(wire, nil); negotiated != 4 {
		t.Errorf("negotiated = %d with a version 4 peer speaking 3, want 4", negotiated)
	}
}

func TestIPWireBytes(t *testing.T) {
	if got := IPWireBytes(1200, false); got != 1228 {
		t.Errorf("direct: %d, want 1228", got)
	}
	// 1228 pads to 1232, plus 32 of WireGuard and 28 of outer UDP/IPv4.
	if got := IPWireBytes(1200, true); got != 1292 {
		t.Errorf("through WireGuard: %d, want 1292", got)
	}
	// Already a multiple of 16: no padding.
	if got := IPWireBytes(1220, true); got != 1308 {
		t.Errorf("through WireGuard, no padding: %d, want 1308", got)
	}
}
