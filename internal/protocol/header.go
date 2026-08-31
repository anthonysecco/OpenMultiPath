// Package protocol defines the OpenMultiPath wire header, which sits
// between the outer UDP header and the WireGuard packet it carries.
//
// The header is deliberately not encrypted or authenticated: WireGuard
// already protects the payload, and this layer only carries scheduling and
// measurement metadata. See protocol.md - "Do not write crypto."
//
// Layout, all integers big-endian:
//
//	base header, 15 bytes, on every packet
//	  0       version (high 4 bits) | type (low 4 bits)
//	  1       flags: bit0 echo block present, bits1-2 class, bits3-7 reserved
//	  2       path id
//	  3-6     global sequence, assigned once before path selection
//	  7-10    per-path sequence, assigned at transmit on one specific path
//	  11-14   send timestamp, microseconds on the sender's own clock
//
//	echo block, present only when the echo flag is set
//	  0       entry count
//	  then per entry, 9 bytes each:
//	    0     path id the entry refers to
//	    1-4   the send timestamp being echoed back
//	    5-8   microseconds the peer held it between arrival and this transmit
//
// Two sequence numbers are carried because a gap in the global sequence
// means almost nothing - reordering across paths is normal - while the
// per-path sequence is strictly monotonic per path, so any gap there is
// real loss on that path.
//
// The echo block is what makes delay measurement work without synchronised
// clocks. Combined with the receiver's own arrival reading it gives the
// four-timestamp model used by NTP and TWAMP: the peer's hold time is
// reported explicitly so it can be subtracted out. Sender clocks are only
// ever compared against themselves, never against each other.
//
// Carrying the echo on every packet would waste bandwidth at data rates,
// so it is optional and attached roughly ten times a second, covering
// every path with something to report in a single entry list. That gives
// the sender one consistent snapshot rather than per-path readings taken
// at slightly different moments.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Version is the current wire version. It is carried so the format can
// change later without guesswork about what a peer is speaking.
const Version = 1

// Packet types. Only TypeData is generated today; the rest are reserved so
// the field does not have to be retrofitted once probing lands.
const (
	TypeData   uint8 = 0
	TypeProbe  uint8 = 1
	TypeReport uint8 = 2
)

// Traffic classes. Classification is a later step, so everything currently
// goes out as ClassUnknown.
const (
	ClassUnknown  uint8 = 0
	ClassRealtime uint8 = 1
	ClassBulk     uint8 = 2
)

// BaseLen is the size of the header carried on every packet, excluding any
// echo block.
const BaseLen = 15

// EchoEntryLen is the size of a single echo entry.
const EchoEntryLen = 9

const (
	flagEcho   = 1 << 0
	classShift = 1
	classMask  = 0x3
)

var (
	// ErrShort means the buffer is too small to hold what the header
	// claims. Treated as a malformed packet and dropped.
	ErrShort = errors.New("protocol: packet shorter than header")

	// ErrVersion means the peer is speaking a wire version this build does
	// not understand.
	ErrVersion = errors.New("protocol: unsupported header version")
)

// EchoEntry reports what the sender saw on one path, so the peer can
// compute a round trip time for that path without synchronised clocks.
type EchoEntry struct {
	// PathID is the path this entry describes.
	PathID uint8

	// TS is the peer's own send timestamp being echoed back to them.
	TS uint32

	// Delay is how long we held the packet, in microseconds, between
	// receiving it and transmitting this echo. Subtracting it removes our
	// own think time from the peer's round trip calculation.
	Delay uint32
}

// Header is the parsed form of the wire header.
type Header struct {
	Type   uint8
	Class  uint8
	PathID uint8

	// GlobalSeq is assigned once per packet, before path selection, and is
	// what a future resequencer will order bulk traffic by.
	GlobalSeq uint32

	// PathSeq is assigned at transmit on one specific path. Gaps are
	// unambiguous loss on that path.
	PathSeq uint32

	// SendTS is microseconds on the sender's own monotonic clock. It is
	// only ever compared against other readings from that same sender, so
	// the two ends need no shared epoch.
	SendTS uint32

	// Echo carries measurement feedback for the peer, when present.
	Echo []EchoEntry
}

// AppendTo appends the encoded header to dst and returns the extended
// slice. Passing a slice with spare capacity avoids allocating per packet.
func (h *Header) AppendTo(dst []byte) []byte {
	flags := byte(0)
	if len(h.Echo) > 0 {
		flags |= flagEcho
	}
	flags |= (h.Class & classMask) << classShift

	dst = append(dst,
		Version<<4|(h.Type&0x0f),
		flags,
		h.PathID,
	)
	dst = binary.BigEndian.AppendUint32(dst, h.GlobalSeq)
	dst = binary.BigEndian.AppendUint32(dst, h.PathSeq)
	dst = binary.BigEndian.AppendUint32(dst, h.SendTS)

	if len(h.Echo) > 0 {
		dst = append(dst, uint8(len(h.Echo)))
		for _, e := range h.Echo {
			dst = append(dst, e.PathID)
			dst = binary.BigEndian.AppendUint32(dst, e.TS)
			dst = binary.BigEndian.AppendUint32(dst, e.Delay)
		}
	}
	return dst
}

// Parse decodes a header from the front of b and returns it along with the
// payload that follows. The returned payload aliases b.
func Parse(b []byte) (Header, []byte, error) {
	var h Header
	if len(b) < BaseLen {
		return h, nil, ErrShort
	}
	if v := b[0] >> 4; v != Version {
		return h, nil, fmt.Errorf("%w: %d", ErrVersion, v)
	}

	h.Type = b[0] & 0x0f
	flags := b[1]
	h.Class = (flags >> classShift) & classMask
	h.PathID = b[2]
	h.GlobalSeq = binary.BigEndian.Uint32(b[3:7])
	h.PathSeq = binary.BigEndian.Uint32(b[7:11])
	h.SendTS = binary.BigEndian.Uint32(b[11:15])

	rest := b[BaseLen:]
	if flags&flagEcho == 0 {
		return h, rest, nil
	}

	if len(rest) < 1 {
		return h, nil, ErrShort
	}
	count := int(rest[0])
	rest = rest[1:]
	if len(rest) < count*EchoEntryLen {
		return h, nil, ErrShort
	}
	h.Echo = make([]EchoEntry, count)
	for i := range h.Echo {
		e := rest[i*EchoEntryLen:]
		h.Echo[i] = EchoEntry{
			PathID: e[0],
			TS:     binary.BigEndian.Uint32(e[1:5]),
			Delay:  binary.BigEndian.Uint32(e[5:9]),
		}
	}
	return h, rest[count*EchoEntryLen:], nil
}

// SeqAfter reports whether a comes after b, tolerating the wrap that
// happens every 2^32 packets. Comparing the two with > directly would
// misread every packet after a wrap as ancient, which on a link carrying a
// couple of thousand packets a second means a few weeks of uptime - the
// worst possible time to discover it.
func SeqAfter(a, b uint32) bool {
	return int32(a-b) > 0
}

// MicrosSince returns the microseconds elapsed between two timestamps taken
// from the same clock.
//
// Timestamps are truncated to 32 bits and so wrap about every 71 minutes.
// Unsigned subtraction yields the correct delta across a wrap for any
// interval under roughly 35 minutes, which every interval this is used for
// - round trips, hold times, queue delay windows - is by orders of
// magnitude. Do not "fix" this by widening or by comparing the operands.
func MicrosSince(later, earlier uint32) uint32 {
	return later - earlier
}
