package classify

import "testing"

// Everything else that shares a media port must not read as RTP. This is
// the check that makes rtp.go safe to put ahead of the behavioural test:
// if QUIC could pass it, every download would be called a call.
func TestOnlyRTPHasRTPsVersionBits(t *testing.T) {
	for name, b0 := range map[string]byte{
		"QUIC long header":  0xc3,
		"QUIC initial":      0xc0,
		"QUIC short header": 0x5f,
		"QUIC short, alt":   0x40,
		"STUN":              0x00,
		"DTLS handshake":    0x16,
		"DTLS application":  0x17,
		"RTP version 0":     0x00,
		"RTP version 1":     0x40,
		"RTP version 3":     0xc0,
	} {
		p := make([]byte, 64)
		p[0] = b0
		p[1] = 96
		if _, _, ok := rtpHeader(p); ok {
			t.Errorf("%s (first byte %#02x) was read as RTP", name, b0)
		}
	}

	good := make([]byte, 64)
	good[0], good[1] = 0x80, 96
	if _, _, ok := rtpHeader(good); !ok {
		t.Error("a well-formed RTP packet was rejected")
	}
}

// RFC 3551 leaves payload types 72-76 unassigned for RTP precisely so RTCP
// can share a port unambiguously. Reading an RTCP report as media would be
// classifying on the wrong evidence.
func TestRTCPPayloadTypesAreNotMedia(t *testing.T) {
	for pt := byte(72); pt <= 76; pt++ {
		p := make([]byte, 64)
		p[0], p[1] = 0x80, pt
		if _, _, ok := rtpHeader(p); ok {
			t.Errorf("payload type %d was read as RTP media", pt)
		}
	}
	for _, pt := range []byte{0, 8, 96, 111, 127} {
		p := make([]byte, 64)
		p[0], p[1] = 0x80, pt
		if _, _, ok := rtpHeader(p); !ok {
			t.Errorf("payload type %d was rejected, but it is ordinary media", pt)
		}
	}
}

func TestShortPayloadIsNotRTP(t *testing.T) {
	for n := 0; n < rtpHeaderLen; n++ {
		p := make([]byte, n)
		if n > 0 {
			p[0] = 0x80
		}
		if _, _, ok := rtpHeader(p); ok {
			t.Errorf("a %d byte payload was read as RTP", n)
		}
	}
}

// One packet matching is weak evidence - a quarter of random payloads have
// the right two bits. Three sharing a 32-bit SSRC is not chance.
func TestRTPNeedsAConsistentStreamNotOnePacket(t *testing.T) {
	f := &flow{}
	if f.noteRTP(rtpPayload(96, 1, 0xaabbccdd, 200)) {
		t.Error("a single packet confirmed RTP")
	}
	if f.noteRTP(rtpPayload(96, 2, 0xaabbccdd, 200)) {
		t.Error("two packets confirmed RTP")
	}
	if !f.noteRTP(rtpPayload(96, 3, 0xaabbccdd, 200)) {
		t.Error("three consistent packets did not confirm RTP")
	}
}

// A run only counts while it is the same stream. Random payloads that
// happen to have the right bits will disagree on SSRC.
func TestRTPRunResetsWhenTheStreamChanges(t *testing.T) {
	f := &flow{}
	f.noteRTP(rtpPayload(96, 1, 0x11111111, 200))
	f.noteRTP(rtpPayload(96, 2, 0x22222222, 200)) // different source
	if f.noteRTP(rtpPayload(96, 3, 0x33333333, 200)) {
		t.Error("three packets from three different sources confirmed one stream")
	}
}

// A 16-bit sequence wraps every 65536 packets, about twenty minutes of
// audio. A call must not be reclassified because of it.
func TestSequenceWrapDoesNotBreakTheStream(t *testing.T) {
	f := &flow{}
	const ssrc = 0x0badf00d
	f.noteRTP(rtpPayload(96, 65534, ssrc, 200))
	f.noteRTP(rtpPayload(96, 65535, ssrc, 200))
	if !f.noteRTP(rtpPayload(96, 0, ssrc, 200)) {
		t.Error("the stream was lost at the sequence-number wrap")
	}
}

// Media is interleaved with RTCP and STUN keepalives all through a call.
// Those must not erase evidence already gathered.
func TestInterleavedNonMediaDoesNotEraseEvidence(t *testing.T) {
	f := &flow{}
	const ssrc = 0x5eed
	f.noteRTP(rtpPayload(96, 1, ssrc, 200))
	f.noteRTP(stunBinding()) // a keepalive mid-call
	f.noteRTP(rtpPayload(96, 2, ssrc, 200))
	f.noteRTP(stunBinding()) // and another
	if !f.noteRTP(rtpPayload(96, 3, ssrc, 200)) {
		t.Error("keepalives between media packets reset the run")
	}

	// The keepalives themselves must not count toward it, though: three
	// media packets are required, not three packets of any kind.
	g := &flow{}
	g.noteRTP(rtpPayload(96, 1, ssrc, 200))
	g.noteRTP(stunBinding())
	if g.noteRTP(stunBinding()) {
		t.Error("keepalives counted as media evidence")
	}
}
