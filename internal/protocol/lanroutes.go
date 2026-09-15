package protocol

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net/netip"
	"sort"
)

// LAN subnets (D-068). Not tied to a wire version: see TypeLANRoutes.
//
// Home routes the vehicle's LAN subnets back down the tunnel, and until now
// it was told them by hand. The LAN tab (D-067) lets them change from the
// vehicle, so the vehicle tells home, the same way it tells home its link
// speeds (D-055): the complete set, identified by a digest of its contents,
// repeated until home acknowledges that digest and then not at all until the
// set changes.
//
// The acknowledgement also says which subnets home actually routed. Home
// refuses a subnet that collides with its own networks, and that refusal has
// to be visible on the vehicle, where the person who chose the subnet is.
//
//	TypeLANRoutes payload
//	  0-3     digest of the set, see LANRoutesDigest
//	  4       entry count
//	  then per entry, 5 bytes each:
//	    0-3   network address, IPv4
//	    4     prefix length
//
//	TypeLANRoutesAck payload
//	  0-3     the digest now held
//	  4-7     bit i set when entry i, in the set's sorted order, was routed

// LANRouteEntryLen is the size of one entry in a TypeLANRoutes payload.
const LANRouteEntryLen = 5

// MaxLANRoutes bounds the set. The acknowledgement's mask has 32 bits, and
// no vehicle has more than a handful of LANs.
const MaxLANRoutes = 32

// SortLANRoutes orders a set by address then length, masked, so one set
// always encodes, digests and indexes the same way at both ends.
func SortLANRoutes(set []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(set))
	for _, p := range set {
		if p.Addr().Is4() {
			out = append(out, p.Masked())
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr() != out[j].Addr() {
			return out[i].Addr().Less(out[j].Addr())
		}
		return out[i].Bits() < out[j].Bits()
	})
	if len(out) > MaxLANRoutes {
		out = out[:MaxLANRoutes]
	}
	return out
}

func appendLANEntries(dst []byte, set []netip.Prefix) []byte {
	for _, p := range set {
		a := p.Addr().As4()
		dst = append(dst, a[:]...)
		dst = append(dst, uint8(p.Bits()))
	}
	return dst
}

// LANRoutesDigest identifies a set by its contents.
func LANRoutesDigest(set []netip.Prefix) uint32 {
	h := fnv.New32a()
	h.Write([]byte("lan"))
	h.Write(appendLANEntries(nil, SortLANRoutes(set)))
	return h.Sum32()
}

// AppendLANRoutes encodes a TypeLANRoutes payload.
func AppendLANRoutes(dst []byte, set []netip.Prefix) []byte {
	set = SortLANRoutes(set)
	dst = binary.BigEndian.AppendUint32(dst, LANRoutesDigest(set))
	dst = append(dst, uint8(len(set)))
	return appendLANEntries(dst, set)
}

// ParseLANRoutes decodes a TypeLANRoutes payload. The set comes back in its
// sorted order, which is the order the acknowledgement's mask refers to.
func ParseLANRoutes(b []byte) (digest uint32, set []netip.Prefix, err error) {
	if len(b) < 5 {
		return 0, nil, ErrShort
	}
	digest = binary.BigEndian.Uint32(b[:4])
	count := int(b[4])
	if count > MaxLANRoutes {
		return 0, nil, fmt.Errorf("%w: %d LAN route entries", ErrMalformed, count)
	}
	rest := b[5:]
	if len(rest) < count*LANRouteEntryLen {
		return 0, nil, ErrShort
	}
	set = make([]netip.Prefix, count)
	for i := range set {
		e := rest[i*LANRouteEntryLen:]
		bits := int(e[4])
		if bits > 32 {
			return 0, nil, fmt.Errorf("%w: prefix length %d", ErrMalformed, bits)
		}
		set[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte(e[0:4])), bits).Masked()
	}
	set = SortLANRoutes(set)
	if LANRoutesDigest(set) != digest {
		return 0, nil, fmt.Errorf("%w: LAN route digest does not match its entries", ErrMalformed)
	}
	return digest, set, nil
}

// AppendLANRoutesAck encodes a TypeLANRoutesAck payload.
func AppendLANRoutesAck(dst []byte, digest, routed uint32) []byte {
	dst = binary.BigEndian.AppendUint32(dst, digest)
	return binary.BigEndian.AppendUint32(dst, routed)
}

// ParseLANRoutesAck decodes a TypeLANRoutesAck payload.
func ParseLANRoutesAck(b []byte) (digest, routed uint32, err error) {
	if len(b) < 8 {
		return 0, 0, ErrShort
	}
	return binary.BigEndian.Uint32(b[:4]), binary.BigEndian.Uint32(b[4:8]), nil
}
