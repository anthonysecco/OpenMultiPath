package protocol

import (
	"errors"
	"net/netip"
	"testing"
)

func TestLANRoutesRoundTrip(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("192.168.50.0/24"),
		netip.MustParsePrefix("10.0.1.7/24"), // unmasked on purpose
		netip.MustParsePrefix("10.0.0.0/24"),
	}
	b := AppendLANRoutes(nil, in)
	if len(b) != 5+3*LANRouteEntryLen {
		t.Fatalf("encoded %d bytes", len(b))
	}
	digest, set, err := ParseLANRoutes(b)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/24", "10.0.1.0/24", "192.168.50.0/24"}
	for i, p := range set {
		if p.String() != want[i] {
			t.Errorf("entry %d = %s, want %s", i, p, want[i])
		}
	}
	if digest != LANRoutesDigest(in) {
		t.Error("digest differs from the digest of the unsorted input")
	}

	ack := AppendLANRoutesAck(nil, digest, 0b101)
	d, routed, err := ParseLANRoutesAck(ack)
	if err != nil || d != digest || routed != 0b101 {
		t.Errorf("ack = %x %b %v", d, routed, err)
	}
}

func TestLANRoutesRejectsCorruption(t *testing.T) {
	b := AppendLANRoutes(nil, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")})
	b[7] ^= 1
	if _, _, err := ParseLANRoutes(b); !errors.Is(err, ErrMalformed) {
		t.Errorf("a corrupted entry parsed: %v", err)
	}
	b = AppendLANRoutes(nil, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")})
	b[9] = 40
	if _, _, err := ParseLANRoutes(b); !errors.Is(err, ErrMalformed) {
		t.Errorf("a /40 parsed: %v", err)
	}
	if _, _, err := ParseLANRoutes(b[:6]); !errors.Is(err, ErrShort) {
		t.Errorf("a truncated set parsed: %v", err)
	}
	huge := []byte{0, 0, 0, 0, MaxLANRoutes + 1}
	if _, _, err := ParseLANRoutes(huge); !errors.Is(err, ErrMalformed) {
		t.Errorf("an oversized count parsed: %v", err)
	}
}

// The empty set is a real set - the vehicle has removed every managed LAN -
// and must be distinguishable from any other.
func TestLANRoutesEmptySet(t *testing.T) {
	b := AppendLANRoutes(nil, nil)
	d, set, err := ParseLANRoutes(b)
	if err != nil || len(set) != 0 {
		t.Fatalf("empty set: %v %v", set, err)
	}
	if d == LANRoutesDigest([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}) {
		t.Error("the empty set digests like a non-empty one")
	}
}
