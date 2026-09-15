package protocol

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func key(b byte) (k [32]byte) {
	for i := range k {
		k[i] = b
	}
	return k
}

func TestTransportsRoundTrip(t *testing.T) {
	in := []Transport{
		{PathID: 2, PublicKey: key(3), Addr: netip.MustParseAddr("10.20.1.4"), ISP: "T-Mobile"},
		{PathID: 0, PublicKey: key(1), Addr: netip.MustParseAddr("10.20.1.2"), ISP: "AT&T Mobility"},
		{PathID: 1, PublicKey: key(2), Addr: netip.MustParseAddr("10.20.1.3")},
	}
	b := AppendTransports(nil, in)
	digest, got, err := ParseTransports(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].ISP != "AT&T Mobility" || got[1].ISP != "" || got[2].PublicKey != key(3) || got[2].Addr.String() != "10.20.1.4" {
		t.Errorf("round trip: %+v", got)
	}
	if digest != TransportsDigest(in) {
		t.Error("digest depends on order")
	}
	changed := append([]Transport(nil), in...)
	changed[1].ISP = "AT&T"
	if TransportsDigest(changed) == digest {
		t.Error("an ISP name change does not change the digest, so home would never hear it")
	}
	d, mask, err := ParseTransportsAck(AppendTransportsAck(nil, digest, 0b110))
	if err != nil || d != digest || mask != 0b110 {
		t.Errorf("ack: %x %b %v", d, mask, err)
	}
}

func TestTransportsTruncatesLongNamesAtARune(t *testing.T) {
	name := strings.Repeat("é", 30) // 60 bytes
	b := AppendTransports(nil, []Transport{{PathID: 0, Addr: netip.MustParseAddr("10.20.1.2"), ISP: name}})
	_, got, err := ParseTransports(b)
	if err != nil {
		t.Fatal(err)
	}
	// 20 whole two-byte runes fit in 40 bytes exactly; none may be dropped.
	if got[0].ISP != strings.Repeat("é", 20) {
		t.Errorf("name cut badly: %q (%d bytes)", got[0].ISP, len(got[0].ISP))
	}
}

func TestTransportsCutsAPartRuneOnly(t *testing.T) {
	name := "a" + strings.Repeat("é", 30) // the 40-byte cut splits a rune
	if got := truncateName(name); got != "a"+strings.Repeat("é", 19) {
		t.Errorf("got %q", got)
	}
}

func TestTransportsRejectsCorruption(t *testing.T) {
	b := AppendTransports(nil, []Transport{{PathID: 0, PublicKey: key(9), Addr: netip.MustParseAddr("10.20.1.2"), ISP: "x"}})
	c := append([]byte(nil), b...)
	c[10] ^= 1
	if _, _, err := ParseTransports(c); !errors.Is(err, ErrMalformed) {
		t.Errorf("a flipped key byte parsed: %v", err)
	}
	if _, _, err := ParseTransports(b[:20]); !errors.Is(err, ErrShort) {
		t.Errorf("truncated list parsed: %v", err)
	}
	c = append([]byte(nil), b...)
	c[5+37] = MaxISPNameLen + 1
	if _, _, err := ParseTransports(c); !errors.Is(err, ErrMalformed) {
		t.Errorf("oversized name length parsed: %v", err)
	}
	if _, _, err := ParseTransports([]byte{0, 0, 0, 0, MaxTransports + 1}); !errors.Is(err, ErrMalformed) {
		t.Errorf("oversized count parsed: %v", err)
	}
}
