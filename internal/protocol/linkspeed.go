package protocol

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"sort"
)

// Link speeds, version 4 (D-055).
//
// The vehicle measures each link's speed in both directions with the flow
// test and shapes its own sends to 95% of the upload figure. Home has to
// shape its sends on the same link to 95% of the download figure, and has no
// way to measure it itself - the test is run from the vehicle, which owns the
// links. So the vehicle tells it.
//
// Only when something changed. A TypeLinkSpeed packet carries the complete
// set, identified by a digest of its contents, and home answers every one with
// a TypeLinkSpeedAck naming the digest it now holds. The vehicle repeats the
// set until that acknowledgement arrives and then goes quiet, so a link whose
// speeds never change costs nothing on the wire after the first exchange. It
// is not a single unprompted push: D-053 found that is exactly the packet a
// stressed link drops.
//
//	TypeLinkSpeed payload
//	  0-3     digest of the set, see LinkSpeedDigest
//	  4       entry count
//	  then per entry, 13 bytes each:
//	    0     path id
//	    1-4   upload, vehicle to home, kbps, 0 for never measured
//	    5-8   download, home to vehicle, kbps, 0 for never measured
//	    9-12  when it was measured, unix seconds
//
//	TypeLinkSpeedAck payload
//	  0-3     the digest now held

// LinkSpeedEntryLen is the size of one entry in a TypeLinkSpeed payload.
const LinkSpeedEntryLen = 13

// MaxLinkSpeedEntries bounds the set, so a claimed count arriving off the
// network is never trusted to size an allocation.
const MaxLinkSpeedEntries = 32

// LinkSpeed is one path's measured speed in each direction. Zero in a
// direction means it has never been measured, which every reader treats as
// unlimited.
type LinkSpeed struct {
	PathID       uint8
	UpKbps       uint32
	DownKbps     uint32
	MeasuredUnix uint32
}

// sortLinkSpeeds orders a set by path id, so one set always encodes, and so
// digests, the same way.
func sortLinkSpeeds(set []LinkSpeed) []LinkSpeed {
	out := append([]LinkSpeed(nil), set...)
	sort.Slice(out, func(i, j int) bool { return out[i].PathID < out[j].PathID })
	return out
}

func appendEntries(dst []byte, set []LinkSpeed) []byte {
	for _, e := range set {
		dst = append(dst, e.PathID)
		dst = binary.BigEndian.AppendUint32(dst, e.UpKbps)
		dst = binary.BigEndian.AppendUint32(dst, e.DownKbps)
		dst = binary.BigEndian.AppendUint32(dst, e.MeasuredUnix)
	}
	return dst
}

// LinkSpeedDigest identifies a set by its contents. Content rather than a
// counter, so a vehicle that restarts with the same measurements on disk
// produces the digest home already holds and nothing needs resending.
func LinkSpeedDigest(set []LinkSpeed) uint32 {
	h := fnv.New32a()
	h.Write(appendEntries(nil, sortLinkSpeeds(set)))
	return h.Sum32()
}

// AppendLinkSpeed encodes a TypeLinkSpeed payload. A set larger than
// MaxLinkSpeedEntries is truncated to the lowest path ids; there are never
// more than a handful of links.
func AppendLinkSpeed(dst []byte, set []LinkSpeed) []byte {
	set = sortLinkSpeeds(set)
	if len(set) > MaxLinkSpeedEntries {
		set = set[:MaxLinkSpeedEntries]
	}
	dst = binary.BigEndian.AppendUint32(dst, LinkSpeedDigest(set))
	dst = append(dst, uint8(len(set)))
	return appendEntries(dst, set)
}

// ParseLinkSpeed decodes a TypeLinkSpeed payload.
func ParseLinkSpeed(b []byte) (digest uint32, set []LinkSpeed, err error) {
	if len(b) < 5 {
		return 0, nil, ErrShort
	}
	digest = binary.BigEndian.Uint32(b[:4])
	count := int(b[4])
	if count > MaxLinkSpeedEntries {
		return 0, nil, fmt.Errorf("%w: %d link speed entries", ErrMalformed, count)
	}
	rest := b[5:]
	if len(rest) < count*LinkSpeedEntryLen {
		return 0, nil, ErrShort
	}
	set = make([]LinkSpeed, count)
	for i := range set {
		e := rest[i*LinkSpeedEntryLen:]
		set[i] = LinkSpeed{
			PathID:       e[0],
			UpKbps:       binary.BigEndian.Uint32(e[1:5]),
			DownKbps:     binary.BigEndian.Uint32(e[5:9]),
			MeasuredUnix: binary.BigEndian.Uint32(e[9:13]),
		}
	}
	// A digest that does not match its own entries is a corrupt packet, and
	// acknowledging it would tell the vehicle home holds a set it does not.
	if LinkSpeedDigest(set) != digest {
		return 0, nil, fmt.Errorf("%w: link speed digest does not match its entries", ErrMalformed)
	}
	return digest, set, nil
}

// AppendLinkSpeedAck encodes a TypeLinkSpeedAck payload.
func AppendLinkSpeedAck(dst []byte, digest uint32) []byte {
	return binary.BigEndian.AppendUint32(dst, digest)
}

// ParseLinkSpeedAck decodes a TypeLinkSpeedAck payload.
func ParseLinkSpeedAck(b []byte) (uint32, error) {
	if len(b) < 4 {
		return 0, ErrShort
	}
	return binary.BigEndian.Uint32(b[:4]), nil
}

// Overheads between a UDP payload and the physical link, for turning a
// payload size into what the link actually carries at the IP layer.
const (
	// UDPIPv4Overhead is one IPv4 header without options plus one UDP header.
	UDPIPv4Overhead = 28

	// WireGuardOverhead is WireGuard's own framing on a transport packet:
	// a 16-byte message header and a 16-byte Poly1305 tag. Its outer UDP/IPv4
	// header is UDPIPv4Overhead again, counted separately.
	WireGuardOverhead = 32
)

// IPWireBytes is what a UDP datagram carrying payload bytes occupies on the
// physical link at the IP layer.
//
// throughWireGuard is whether the datagram is sent over a WireGuard interface
// rather than straight out the physical one. Then it becomes WireGuard's
// plaintext - padded to a multiple of 16 bytes - and gains WireGuard's framing
// and a second UDP/IPv4 header on the way out. Link-layer framing (Ethernet,
// PPPoE, the cellular bearer's own) is not counted: the flow test measures at
// the IP layer too, so the two agree.
//
// The padding is rounded up without capping at the interface MTU, which
// WireGuard does. That overstates a full-sized packet by at most 15 bytes, in
// the safe direction.
func IPWireBytes(payload int, throughWireGuard bool) int {
	inner := payload + UDPIPv4Overhead
	if !throughWireGuard {
		return inner
	}
	padded := (inner + 15) &^ 15
	return padded + WireGuardOverhead + UDPIPv4Overhead
}
