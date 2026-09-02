package classify

import (
	"encoding/binary"
	"testing"
)

func stunOfType(typ uint16, bodyLen int, payloadLen int) []byte {
	p := make([]byte, payloadLen)
	binary.BigEndian.PutUint16(p[0:2], typ)
	binary.BigEndian.PutUint16(p[2:4], uint16(bodyLen))
	binary.BigEndian.PutUint32(p[4:8], stunMagicCookie)
	return p
}

// All four binding message types mean the same thing here: this port pair
// is running ICE. The class bits that separate a request from its response
// are deliberately not examined, because either direction is equally good
// evidence and the responder sees the response first.
func TestEveryBindingClassIsRecognised(t *testing.T) {
	for name, typ := range map[string]uint16{
		"request":          0x0001,
		"indication":       0x0011,
		"success response": 0x0101,
		"error response":   0x0111,
	} {
		if !isSTUNBinding(stunOfType(typ, 0, stunHeaderLen)) {
			t.Errorf("binding %s (type %#04x) was not recognised as STUN", name, typ)
		}
	}
}

// RFC 7983's demultiplexing rules. STUN, DTLS and RTP share a port in every
// WebRTC session, and the leading bits are what separate them. An RTP packet
// misread as STUN would classify on the wrong evidence entirely.
func TestOtherProtocolsSharingThePortAreNotSTUN(t *testing.T) {
	rtp := stunOfType(0x0001, 0, stunHeaderLen)
	rtp[0] = 0x80 // RTP version 2 in the top two bits
	if isSTUNBinding(rtp) {
		t.Error("an RTP packet was read as STUN; the top two bits are what tell them apart")
	}

	dtls := stunOfType(0x0001, 0, stunHeaderLen)
	dtls[0] = 22 // DTLS handshake content type
	if isSTUNBinding(dtls) {
		t.Error("a DTLS record was read as STUN")
	}
}

func TestNonSTUNPayloadsAreRejected(t *testing.T) {
	noCookie := stunOfType(0x0001, 0, stunHeaderLen)
	binary.BigEndian.PutUint32(noCookie[4:8], 0xdeadbeef)

	cases := map[string][]byte{
		"empty":                                   {},
		"shorter than a header":                   make([]byte, stunHeaderLen-1),
		"wrong magic cookie":                      noCookie,
		"body length not a multiple of four":      stunOfType(0x0001, 3, stunHeaderLen+4),
		"body length past the end of the payload": stunOfType(0x0001, 64, stunHeaderLen),
		"a TURN method rather than binding":       stunOfType(0x0003, 0, stunHeaderLen),
	}
	for name, p := range cases {
		if isSTUNBinding(p) {
			t.Errorf("%s was accepted as a STUN binding message", name)
		}
	}
}

// A binding message padded by attributes, or sharing a datagram, still
// counts. Requiring an exact length match would reject real traffic.
func TestBindingWithAttributesIsRecognised(t *testing.T) {
	if !isSTUNBinding(stunOfType(0x0001, 8, stunHeaderLen+8)) {
		t.Error("a binding request carrying attributes was rejected")
	}
	if !isSTUNBinding(stunOfType(0x0001, 8, stunHeaderLen+64)) {
		t.Error("a binding request in a longer datagram was rejected")
	}
}
