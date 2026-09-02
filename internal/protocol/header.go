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
//	report block, present only when the report flag is set (version 2)
//	  0       entry count
//	  then per entry, 10 bytes each - what we measured on the peer's
//	  transmissions to us, which is the peer's send direction:
//	    0     path id the entry refers to
//	    1-2   p95 transit spread above this path's own floor, 0.1 ms units
//	    3-4   queue delay above this path's own floor, 0.1 ms units
//	    5-6   interarrival jitter, 0.1 ms units
//	    7-8   recent loss, parts per thousand
//	    9     burst ratio, tenths
//
//	auth tag, present only when the auth flag is set (version 2)
//	  8 bytes, HMAC-SHA256 over every header byte preceding it, truncated
//
// The report block is the answer to a problem the echo block cannot solve.
// A round trip is a round trip: it says nothing about which direction the
// delay is in. A sender choosing which path to transmit on was therefore
// making an outbound decision from inbound evidence, and on the road that
// produced exactly the failure you would predict - a download saturating a
// path's downlink drove the flow off that path's perfectly healthy uplink
// and onto a 512 kbps standby link.
//
// The receiver already measures everything needed; it simply never said so.
// Every figure in the report is a difference against the reporting path's
// own floor, so the unknown offset between the two clocks cancels and no
// synchronisation is required - the same property the echo block relies on.
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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Version is the wire version this build emits once it knows the peer can
// read it. MinVersion is the oldest it still accepts.
//
// Both are needed because an upgrade reaches the two ends at different
// moments, and one of them is in a vehicle. Accepting the older version
// while emitting the newer only after hearing it means either end can be
// upgraded first with no outage - scope-v1.md is blunt that a tunnel broken
// from 800 miles away is unrecoverable, and a flag day is exactly how that
// happens.
const (
	Version    = 2
	MinVersion = 1
)

// Packet types. Only TypeData is generated today; the rest are reserved so
// the field does not have to be retrofitted once probing lands.
const (
	TypeData   uint8 = 0
	TypeProbe  uint8 = 1
	TypeReport uint8 = 2
)

// Traffic classes, set by internal/classify from the inner packet.
//
// ClassUnknown is not a placeholder any more, it is a real answer: it means
// the sender could not honestly say. That happens when the daemon runs
// below WireGuard and its payloads are ciphertext, while a flow is still
// being sampled, and for packets that belong to no flow at all. Carrying
// the class is step 7; acting on it is step 8, so nothing downstream
// distinguishes these yet.
const (
	ClassUnknown  uint8 = 0
	ClassRealtime uint8 = 1
	ClassBulk     uint8 = 2
)

// BaseLen is the size of the header carried on every packet, excluding any
// echo block.
const BaseLen = 15

// EchoEntryLen is the size of a single echo entry.
const EchoEntryLen = 11

// MaxEchoEntries caps how many paths one echo block describes. The cap
// exists so the header has a hard maximum size that the MTU budget can be
// computed against, rather than one that grows with the path count. With
// more paths than this, successive reports cover the rest; at ten reports a
// second that costs nothing.
const MaxEchoEntries = 4

// ReportEntryLen is the size of a single path report entry.
const ReportEntryLen = 10

// MaxReportEntries caps how many paths one report block describes, on the
// same reasoning as MaxEchoEntries: a hard maximum the MTU budget can be
// computed against.
const MaxReportEntries = 4

// AuthTagLen is the truncated HMAC carried when a key is configured.
//
// Eight bytes is short for a MAC and deliberately so. It is not protecting
// the payload - WireGuard already does that, and protocol.md is firm about
// not writing crypto here - it is only raising the cost of injecting
// measurement metadata from one packet to 2^64 of them. Against an attacker
// who can already see the traffic that is the wrong defence anyway; against
// blind injection it is ample, and the bytes come out of every packet.
const AuthTagLen = 8

// MaxDataHeaderLen is the largest header a packet carrying tunnel traffic
// can have, and so is what the tunnel MTU must be sized against.
//
// Report blocks ride only on standalone reports, never on data. That split
// is worth the extra constant: folding them into the budget would cost
// every data packet the worst-case report size for the sake of a block sent
// once a second on a packet with no payload at all.
const MaxDataHeaderLen = BaseLen + 1 + MaxEchoEntries*EchoEntryLen + AuthTagLen

// MaxHeaderLen is the largest header of any type, which is what receive
// buffers have to allow for.
const MaxHeaderLen = MaxDataHeaderLen + 1 + MaxReportEntries*ReportEntryLen

const (
	flagEcho   = 1 << 0
	classShift = 1
	classMask  = 0x3
	flagReport = 1 << 3
	flagAuth   = 1 << 4

	// flagCapable advertises that the sender can also read the newest
	// version this build knows, even when the packet itself is encoded as an
	// older one.
	//
	// Without it version negotiation cannot start. Both ends begin by
	// emitting the oldest version, because neither has yet heard the newer
	// one from the other - so neither ever does, and the upgrade never
	// happens. Something has to speak first, and it cannot be a version 2
	// packet, because an un-upgraded peer would drop it.
	//
	// So the advertisement rides in a bit that version 1 already ignores.
	// Its parser reads the echo flag and the class, and pays no attention to
	// bits 3 through 7 - which makes this readable by a new build and
	// invisible to an old one.
	flagCapable = 1 << 5
)

var (
	// ErrShort means the buffer is too small to hold what the header
	// claims. Treated as a malformed packet and dropped.
	ErrShort = errors.New("protocol: packet shorter than header")

	// ErrVersion means the peer is speaking a wire version this build does
	// not understand.
	ErrVersion = errors.New("protocol: unsupported header version")

	// ErrMalformed means the header is self-inconsistent. Dropped.
	ErrMalformed = errors.New("protocol: malformed header")

	// ErrAuth means the header failed authentication while a key was
	// configured. Dropped, and worth counting: a steady trickle is someone
	// probing the port, a flood is an attack, and neither should be
	// invisible.
	ErrAuth = errors.New("protocol: header failed authentication")
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

	// MaxSeen is the largest packet, in bytes on the wire, received on
	// this path since the previous report. It is how a padded MTU probe is
	// confirmed: comparing sizes answers "did my big packet arrive"
	// directly, with none of the ambiguity of matching timestamps against
	// a report that only ever names the most recent packet.
	MaxSeen uint16
}

// ReportEntry is what the sender of this packet measured on the *peer's*
// transmissions over one path. To the peer receiving it, that is a
// description of its own send direction - the thing it could not otherwise
// see, and the thing it needs in order to choose where to send.
//
// Every field is a difference against that path's own floor or a plain
// count, so none of them depend on the two clocks agreeing. There is
// deliberately no absolute one-way delay here: it cannot be measured
// without synchronised clocks, and it is not what the decision turns on.
type ReportEntry struct {
	PathID uint8

	// SpreadTenthMs is the p95 transit above this path's own minimum, in
	// tenths of a millisecond. It is the tail latency the peer's packets
	// actually experienced getting here.
	SpreadTenthMs uint16

	// QueueTenthMs is the most recent transit above the same minimum: how
	// full the link underneath is right now, in the peer's send direction.
	QueueTenthMs uint16

	// JitterTenthMs is the RFC 3550 interarrival estimate.
	JitterTenthMs uint16

	// LossPerMille is recent loss in parts per thousand, giving 0.1%
	// resolution without a float on the wire.
	LossPerMille uint16

	// BurstTenths is how clustered that loss was, in tenths - 10 means
	// scattered exactly as chance would scatter it, higher means runs.
	// Saturates at 25.5, by which point the distinction stopped mattering.
	BurstTenths uint8
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

	// Reports carry what we measured on the peer's transmissions, so the
	// peer can judge its own send direction. Present only on standalone
	// reports, never on data.
	Reports []ReportEntry
}

// AppendTo appends the encoded header to dst and returns the extended
// slice. Passing a slice with spare capacity avoids allocating per packet.
//
// version is what to emit: pass the peer's version once it is known, so a
// peer that cannot read version 2 is never sent it. key authenticates the
// header when non-empty, and is ignored on version 1, which has nowhere to
// put a tag.
func (h *Header) AppendTo(dst []byte, version uint8, key []byte) []byte {
	if version < MinVersion || version > Version {
		version = MinVersion
	}
	reports := h.Reports
	auth := len(key) > 0
	if version < 2 {
		// Neither block exists in version 1. Dropping them is right rather
		// than refusing to encode: the measurements are an optimisation,
		// and a peer that cannot read them still needs its packets.
		reports = nil
		auth = false
	}

	// Advertised on every packet, whatever version this one is encoded as.
	// See flagCapable: it is what lets the two ends find each other.
	flags := byte(flagCapable)
	if len(h.Echo) > 0 {
		flags |= flagEcho
	}
	if len(reports) > 0 {
		flags |= flagReport
	}
	if auth {
		flags |= flagAuth
	}
	flags |= (h.Class & classMask) << classShift

	start := len(dst)
	dst = append(dst,
		version<<4|(h.Type&0x0f),
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
			dst = binary.BigEndian.AppendUint16(dst, e.MaxSeen)
		}
	}

	if len(reports) > 0 {
		dst = append(dst, uint8(len(reports)))
		for _, r := range reports {
			dst = append(dst, r.PathID)
			dst = binary.BigEndian.AppendUint16(dst, r.SpreadTenthMs)
			dst = binary.BigEndian.AppendUint16(dst, r.QueueTenthMs)
			dst = binary.BigEndian.AppendUint16(dst, r.JitterTenthMs)
			dst = binary.BigEndian.AppendUint16(dst, r.LossPerMille)
			dst = append(dst, r.BurstTenths)
		}
	}

	if auth {
		dst = append(dst, tagFor(key, dst[start:])...)
	}
	return dst
}

// tagFor computes the truncated header MAC.
func tagFor(key, header []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(header)
	return m.Sum(nil)[:AuthTagLen]
}

// Parse decodes a header from the front of b and returns it along with the
// payload that follows, and the wire version the peer spoke. The returned
// payload aliases b.
//
// key, when non-empty, authenticates version 2 packets: one without a valid
// tag is rejected. Version 1 packets are accepted unauthenticated, because
// the format has nowhere to carry a tag and refusing them would mean the
// upgrade could never begin. That is a real downgrade path, and it closes
// on its own once both ends speak version 2 - see ompd's peer version
// tracking, which never falls back once it has heard the newer one.
func Parse(b []byte, key []byte) (Header, []byte, uint8, error) {
	var h Header
	if len(b) < BaseLen {
		return h, nil, 0, ErrShort
	}
	version := b[0] >> 4
	if version < MinVersion || version > Version {
		return h, nil, 0, fmt.Errorf("%w: %d", ErrVersion, version)
	}

	// What the peer can read, which is not the same as what this packet is
	// encoded as. A build that advertises capability is telling us we may
	// emit the newest version we know; one that does not is old, and gets
	// exactly what it can parse.
	negotiated := version
	if b[1]&flagCapable != 0 {
		negotiated = Version
	}

	h.Type = b[0] & 0x0f
	flags := b[1]
	h.Class = (flags >> classShift) & classMask
	h.PathID = b[2]
	h.GlobalSeq = binary.BigEndian.Uint32(b[3:7])
	h.PathSeq = binary.BigEndian.Uint32(b[7:11])
	h.SendTS = binary.BigEndian.Uint32(b[11:15])

	rest := b[BaseLen:]

	if flags&flagEcho != 0 {
		if len(rest) < 1 {
			return h, nil, 0, ErrShort
		}
		count := int(rest[0])
		rest = rest[1:]
		// Bound the count before allocating against it. These packets
		// arrive off the open internet, so a claimed length is not a
		// promise.
		if count > MaxEchoEntries {
			return h, nil, 0, fmt.Errorf("%w: %d echo entries", ErrMalformed, count)
		}
		if len(rest) < count*EchoEntryLen {
			return h, nil, 0, ErrShort
		}
		h.Echo = make([]EchoEntry, count)
		for i := range h.Echo {
			e := rest[i*EchoEntryLen:]
			h.Echo[i] = EchoEntry{
				PathID:  e[0],
				TS:      binary.BigEndian.Uint32(e[1:5]),
				Delay:   binary.BigEndian.Uint32(e[5:9]),
				MaxSeen: binary.BigEndian.Uint16(e[9:11]),
			}
		}
		rest = rest[count*EchoEntryLen:]
	}

	if flags&flagReport != 0 {
		if len(rest) < 1 {
			return h, nil, 0, ErrShort
		}
		count := int(rest[0])
		rest = rest[1:]
		if count > MaxReportEntries {
			return h, nil, 0, fmt.Errorf("%w: %d report entries", ErrMalformed, count)
		}
		if len(rest) < count*ReportEntryLen {
			return h, nil, 0, ErrShort
		}
		h.Reports = make([]ReportEntry, count)
		for i := range h.Reports {
			e := rest[i*ReportEntryLen:]
			h.Reports[i] = ReportEntry{
				PathID:        e[0],
				SpreadTenthMs: binary.BigEndian.Uint16(e[1:3]),
				QueueTenthMs:  binary.BigEndian.Uint16(e[3:5]),
				JitterTenthMs: binary.BigEndian.Uint16(e[5:7]),
				LossPerMille:  binary.BigEndian.Uint16(e[7:9]),
				BurstTenths:   e[9],
			}
		}
		rest = rest[count*ReportEntryLen:]
	}

	if flags&flagAuth != 0 {
		if len(rest) < AuthTagLen {
			return h, nil, 0, ErrShort
		}
		tag := rest[:AuthTagLen]
		rest = rest[AuthTagLen:]
		if len(key) > 0 {
			covered := b[:len(b)-len(rest)-AuthTagLen]
			if !hmac.Equal(tag, tagFor(key, covered)) {
				return h, nil, 0, ErrAuth
			}
		}
	} else if len(key) > 0 && version >= 2 {
		// A version 2 peer that knows the key always tags. An untagged one
		// is either misconfigured or forged, and neither should be allowed
		// to feed the scheduler.
		return h, nil, 0, ErrAuth
	}

	return h, rest, negotiated, nil
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
