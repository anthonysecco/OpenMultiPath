package classify

import (
	"encoding/binary"
	"net/netip"
)

// Inner-packet parsing, far enough to get a 5-tuple and a payload.
//
// This is deliberately not a protocol stack. The classifier needs to know
// which conversation a packet belongs to, which direction it was going,
// and where the transport payload starts so STUN can be looked for. It
// needs nothing else, so it parses nothing else - options, extension
// headers, and every field that does not contribute to those three
// answers are stepped over rather than interpreted.

const (
	protoTCP = 6
	protoUDP = 17
)

// FlowKey identifies a conversation, not a direction. The two endpoints
// are stored in a fixed order so that a packet and its reply produce the
// same key, because a call is one flow with traffic in both directions
// and classifying the halves separately would mean a conference's inbound
// audio could be real-time while its outbound audio was not.
//
// Which endpoint sorts first carries no meaning; the ordering exists only
// to make the key canonical. Direction is recovered by comparing the
// packet's source against A, which is what dirOf returns.
type FlowKey struct {
	A, B         netip.Addr
	APort, BPort uint16
	Proto        uint8
}

// direction says which way along a FlowKey a packet was travelling.
type direction uint8

const (
	aToB direction = iota
	bToA
)

// packet is one parsed inner packet, reduced to what classification uses.
type packet struct {
	flow    FlowKey
	dir     direction
	payload []byte // transport payload, empty if the packet carried none
	size    int    // full inner packet length, as the link sees it
}

// parse reduces an inner IP packet to a flow, a direction, and a transport
// payload.
//
// It reports false for anything it cannot place in a conversation: a
// truncated header, a protocol that is neither TCP nor UDP, or a non-first
// fragment, which carries no ports and so cannot be attributed to a flow
// by 5-tuple at all. A caller that cannot identify the flow must not
// guess at the class, so these all end up unclassified rather than
// defaulted to something convenient.
func parse(pkt []byte) (packet, bool) {
	if len(pkt) < 1 {
		return packet{}, false
	}

	var (
		src, dst  netip.Addr
		proto     uint8
		transport []byte
	)

	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return packet{}, false
		}
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl {
			return packet{}, false
		}

		// A fragment other than the first has no transport header, so
		// there are no ports to key on. The fragment offset is the low
		// 13 bits of the flags-and-offset field.
		if binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 {
			return packet{}, false
		}

		proto = pkt[9]
		src = netip.AddrFrom4([4]byte(pkt[12:16]))
		dst = netip.AddrFrom4([4]byte(pkt[16:20]))
		transport = pkt[ihl:]

	case 6:
		// D-026 drops IPv6 on the WAN rather than carrying it, so this
		// should not arrive. It is parsed anyway because the cost is a
		// dozen lines and the alternative failure is silent: if that
		// decision is ever revisited, an unparsed v6 packet would be
		// classified by no signal at all rather than by a wrong one,
		// which is a much harder thing to notice.
		if len(pkt) < 40 {
			return packet{}, false
		}
		proto = pkt[6]
		src = netip.AddrFrom16([16]byte(pkt[8:24]))
		dst = netip.AddrFrom16([16]byte(pkt[24:40]))
		transport = pkt[40:]

	default:
		return packet{}, false
	}

	if proto != protoTCP && proto != protoUDP {
		return packet{}, false
	}
	if len(transport) < 4 {
		return packet{}, false
	}
	sport := binary.BigEndian.Uint16(transport[0:2])
	dport := binary.BigEndian.Uint16(transport[2:4])

	p := packet{size: len(pkt)}
	p.flow, p.dir = keyFor(src, sport, dst, dport, proto)

	if proto == protoUDP {
		if len(transport) < 8 {
			return packet{}, false
		}
		p.payload = transport[8:]
	} else {
		// TCP's data offset is the top nibble of byte 12, in 32-bit
		// words. TCP payloads are never inspected - protocol.md excludes
		// TCP from real-time outright - but the offset is still walked
		// so a caller cannot mistake header bytes for payload.
		if len(transport) < 20 {
			return packet{}, false
		}
		off := int(transport[12]>>4) * 4
		if off < 20 || len(transport) < off {
			return packet{}, false
		}
		p.payload = transport[off:]
	}
	return p, true
}

// keyFor builds the canonical key for a pair of endpoints and reports
// which direction the packet given was travelling.
func keyFor(src netip.Addr, sport uint16, dst netip.Addr, dport uint16, proto uint8) (FlowKey, direction) {
	k := FlowKey{A: src, APort: sport, B: dst, BPort: dport, Proto: proto}
	if !endpointLess(src, sport, dst, dport) {
		k = FlowKey{A: dst, APort: dport, B: src, BPort: sport, Proto: proto}
		return k, bToA
	}
	return k, aToB
}

func endpointLess(a netip.Addr, aport uint16, b netip.Addr, bport uint16) bool {
	if c := a.Compare(b); c != 0 {
		return c < 0
	}
	return aport < bport
}
