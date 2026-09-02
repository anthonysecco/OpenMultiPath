package classify

import "encoding/binary"

// STUN detection, the primary classifier of D-019.
//
// The value here is timing rather than accuracy. Every WebRTC app runs ICE
// connectivity checks before it sends a single media packet, and ICE sends
// those checks from the very port pair the media will use. So a binding
// request is not evidence that a flow is real-time - it is an announcement
// that a real-time flow is about to be born on this exact 5-tuple, arriving
// before the first frame of audio. Every other signal available is
// retrospective by comparison: the behavioural heuristic cannot say
// anything until it has watched a flow for a while, and by then the call
// has already been on the wrong path for that long.
//
// It is also protocol-based rather than vendor-based, which is the reason
// D-019 makes it the foundation and vendor prefixes only a hint. Nothing
// here needs updating when a vendor changes IP ranges, and it works for an
// app nobody configured.

const (
	stunHeaderLen = 20

	// stunMagicCookie is the fixed value at bytes 4:8 of every RFC 5389
	// message. This is the whole discriminator: a 32-bit constant at a
	// known offset makes false positives rare enough to ignore.
	stunMagicCookie = 0x2112A442

	// stunMethodMask isolates the method from the message type, dropping
	// the two class bits that separate a request from its response. All
	// four combinations mean the same thing here - this port pair is
	// doing ICE - so the class is not examined.
	stunMethodMask    = 0x3eef
	stunMethodBinding = 0x0001
)

// isSTUNBinding reports whether a UDP payload is a STUN binding message.
//
// The checks are the standard demultiplexing rules, in cheapest-first
// order. The leading two bits being zero is what RFC 7983 uses to tell
// STUN from RTP (which starts at 128) and DTLS (20 to 63) when all three
// share a port, as they do in every WebRTC session. The magic cookie does
// the real work. The length check is last and catches a payload that
// happens to hold the cookie without being a STUN message.
func isSTUNBinding(payload []byte) bool {
	if len(payload) < stunHeaderLen {
		return false
	}
	if payload[0]&0xc0 != 0 {
		return false
	}
	if binary.BigEndian.Uint32(payload[4:8]) != stunMagicCookie {
		return false
	}
	if binary.BigEndian.Uint16(payload[0:2])&stunMethodMask != stunMethodBinding {
		return false
	}

	// The body length excludes the header and is always a multiple of
	// four, since every attribute is padded to a word boundary. Requiring
	// the datagram to be exactly header plus body would be wrong: an
	// attacker aside, a STUN message can share a datagram with nothing
	// else, but demanding an exact match would reject a message the
	// sender padded. Requiring it to fit is the honest check.
	n := int(binary.BigEndian.Uint16(payload[2:4]))
	if n%4 != 0 || stunHeaderLen+n > len(payload) {
		return false
	}
	return true
}
