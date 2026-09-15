package protocol

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net/netip"
	"sort"
	"unicode/utf8"
)

// The vehicle's WireGuard transports (D-070). Not tied to a wire version, for
// the reason TypeLANRoutes is not.
//
// Each WAN link carries its own WireGuard transport, and home has to hold a
// peer for every one of them before that link can carry anything. When the
// vehicle gains a link it therefore tells home the transport's public key and
// address, and home adds the peer. The same list carries each link's ISP
// name, as ipinfo.io reported it from the link's own egress, so home can name
// its paths the way the vehicle does.
//
// It is the D-055 exchange again: the complete list with a digest, repeated
// until home acknowledges that digest, then silence until it changes.
//
//	TypeTransports payload
//	  0-3     digest of the list, see TransportsDigest
//	  4       entry count
//	  then per entry:
//	    0       path id
//	    1-32    WireGuard public key
//	    33-36   the transport's tunnel address, IPv4
//	    37      ISP name length, n
//	    38-     ISP name, n bytes of UTF-8
//
//	TypeTransportsAck payload
//	  0-3     the digest now held
//	  4-7     bit i set when entry i, in path id order, has a peer at home

// MaxTransports bounds the list: the acknowledgement's mask has 32 bits, and
// a list that size still fits one packet well inside the tunnel's MTU.
const MaxTransports = 12

// MaxISPNameLen bounds a name on the wire. Longer names are cut, at a rune
// boundary.
const MaxISPNameLen = 40

// Transport is one WAN link's WireGuard transport, as home needs to know it.
type Transport struct {
	PathID    uint8
	PublicKey [32]byte
	Addr      netip.Addr
	ISP       string
}

// SortTransports orders a list by path id, cut to MaxTransports with names cut
// to MaxISPNameLen: the order the acknowledgement's mask refers to.
func SortTransports(list []Transport) []Transport {
	out := append([]Transport(nil), list...)
	sort.Slice(out, func(i, j int) bool { return out[i].PathID < out[j].PathID })
	if len(out) > MaxTransports {
		out = out[:MaxTransports]
	}
	for i := range out {
		out[i].ISP = truncateName(out[i].ISP)
	}
	return out
}

func truncateName(s string) string {
	if len(s) <= MaxISPNameLen {
		return s
	}
	b := []byte(s)[:MaxISPNameLen]
	for len(b) > 0 && !utf8.Valid(b) {
		b = b[:len(b)-1]
	}
	return string(b)
}

func appendTransportEntries(dst []byte, list []Transport) []byte {
	for _, t := range list {
		dst = append(dst, t.PathID)
		dst = append(dst, t.PublicKey[:]...)
		a := t.Addr.Unmap()
		if !a.Is4() {
			a = netip.IPv4Unspecified()
		}
		b := a.As4()
		dst = append(dst, b[:]...)
		dst = append(dst, uint8(len(t.ISP)))
		dst = append(dst, t.ISP...)
	}
	return dst
}

// TransportsDigest identifies a list by its contents.
func TransportsDigest(list []Transport) uint32 {
	h := fnv.New32a()
	h.Write([]byte("transports"))
	h.Write(appendTransportEntries(nil, SortTransports(list)))
	return h.Sum32()
}

// AppendTransports encodes a TypeTransports payload.
func AppendTransports(dst []byte, list []Transport) []byte {
	list = SortTransports(list)
	dst = binary.BigEndian.AppendUint32(dst, TransportsDigest(list))
	dst = append(dst, uint8(len(list)))
	return appendTransportEntries(dst, list)
}

// ParseTransports decodes a TypeTransports payload, in path id order.
func ParseTransports(b []byte) (digest uint32, list []Transport, err error) {
	if len(b) < 5 {
		return 0, nil, ErrShort
	}
	digest = binary.BigEndian.Uint32(b[:4])
	count := int(b[4])
	if count > MaxTransports {
		return 0, nil, fmt.Errorf("%w: %d transports", ErrMalformed, count)
	}
	rest := b[5:]
	for i := 0; i < count; i++ {
		if len(rest) < 38 {
			return 0, nil, ErrShort
		}
		var t Transport
		t.PathID = rest[0]
		copy(t.PublicKey[:], rest[1:33])
		t.Addr = netip.AddrFrom4([4]byte(rest[33:37]))
		n := int(rest[37])
		if n > MaxISPNameLen {
			return 0, nil, fmt.Errorf("%w: ISP name of %d bytes", ErrMalformed, n)
		}
		if len(rest) < 38+n {
			return 0, nil, ErrShort
		}
		t.ISP = string(rest[38 : 38+n])
		list = append(list, t)
		rest = rest[38+n:]
	}
	list = SortTransports(list)
	if TransportsDigest(list) != digest {
		return 0, nil, fmt.Errorf("%w: transport digest does not match its entries", ErrMalformed)
	}
	return digest, list, nil
}

// AppendTransportsAck encodes a TypeTransportsAck payload.
func AppendTransportsAck(dst []byte, digest, peered uint32) []byte {
	dst = binary.BigEndian.AppendUint32(dst, digest)
	return binary.BigEndian.AppendUint32(dst, peered)
}

// ParseTransportsAck decodes a TypeTransportsAck payload.
func ParseTransportsAck(b []byte) (digest, peered uint32, err error) {
	if len(b) < 8 {
		return 0, 0, ErrShort
	}
	return binary.BigEndian.Uint32(b[:4]), binary.BigEndian.Uint32(b[4:8]), nil
}
