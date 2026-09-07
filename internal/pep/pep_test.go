package pep

import (
	"net/netip"
	"testing"
)

// The SO_ORIGINAL_DST buffer is a sockaddr_in: family (host order), port
// (network order), address. Getting the byte order wrong sends every proxied
// connection to the wrong place, so it is worth pinning.
func TestDecodeOriginalDst(t *testing.T) {
	// AF_INET=2 (little-endian host), port 8080 = 0x1F90 network order, 1.1.1.1
	m := [16]byte{2, 0, 0x1f, 0x90, 1, 1, 1, 1}
	got, err := decodeOriginalDst(m)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if want := netip.MustParseAddrPort("1.1.1.1:8080"); got != want {
		t.Fatalf("decoded %v, want %v", got, want)
	}
}

func TestDecodeOriginalDstRejectsNonIPv4(t *testing.T) {
	m := [16]byte{10, 0} // AF_INET6 = 10
	if _, err := decodeOriginalDst(m); err == nil {
		t.Fatal("expected an error for a non-IPv4 family")
	}
}
