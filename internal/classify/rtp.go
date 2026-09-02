package classify

import "encoding/binary"

// RTP detection, because packet size does not identify media.
//
// protocol.md's behavioural table describes audio: 60-250 bytes at a
// metronomic 20 ms. That is true of Opus and true of nothing else in a
// conference. Video RTP is MTU-sized, because a frame is fragmented across
// as many packets as it takes, and frame-bursty, because those packets go
// out together and then nothing happens until the next frame. So video
// fails the size test and the gap-variance test both, and a heuristic built
// only on those calls a 1080p stream bulk - which for a project whose
// stated metric is a teleworker's video call is the wrong answer to the
// question that matters most.
//
// STUN covers this for anything WebRTC, since ICE announces the 5-tuple
// before media and video rides the same one. It does not cover a native
// client that never speaks ICE, and - more sharply - it does not cover a
// daemon that started in the middle of an existing call, which is exactly
// the state a restart during a canyon transit leaves behind.
//
// So media is identified from the RTP header instead, which survives all
// of that. It is protocol-based rather than vendor-based, for the reasons
// D-019 gives, and it works on SRTP: the payload is encrypted but the
// header is not, because middleboxes and the receiver's own jitter buffer
// need to read it.

const (
	rtpHeaderLen = 12

	// rtpConfirmRun is how many packets must agree before a flow is called
	// media. One packet matching is weak - a random payload has a one in
	// four chance of the right version bits. Three sharing a 32-bit SSRC
	// is not a coincidence that happens.
	//
	// Three is also cheap in the terms that matter here: at a 20 ms audio
	// cadence it is 60 ms, and video reaches it inside a single frame.
	// Well inside protocol.md's reaction target, and far quicker than the
	// behavioural window it pre-empts.
	rtpConfirmRun = 3

	// rtpSeqWindow bounds how far the sequence number may jump between
	// packets and still look like one stream. Reordering and the odd loss
	// are normal; a leap of thousands means the match was luck.
	rtpSeqWindow = 3000
)

// rtpHeader reads the fields that identify a stream, and reports whether
// the payload is plausibly RTP at all.
func rtpHeader(p []byte) (ssrc uint32, seq uint16, ok bool) {
	if len(p) < rtpHeaderLen {
		return 0, 0, false
	}

	// Version must be 2. This is the check that separates RTP from
	// everything else sharing these ports: QUIC's long header begins 11
	// and its short header 01, while STUN and DTLS both begin 00. Only
	// RTP begins 10.
	if p[0]&0xc0 != 0x80 {
		return 0, 0, false
	}

	// The payload type, with the marker bit masked off. 72 to 76 is the
	// range RTCP occupies when it shares a port, and RFC 3551 leaves it
	// unassigned for RTP precisely so the two can be told apart; treating
	// it as RTP here would be reading an RTCP report as media.
	if pt := p[1] & 0x7f; pt >= 72 && pt <= 76 {
		return 0, 0, false
	}

	return binary.BigEndian.Uint32(p[8:12]), binary.BigEndian.Uint16(p[2:4]), true
}

// noteRTP folds one packet into a flow's RTP evidence and reports whether
// the flow has now proved itself to be media.
func (f *flow) noteRTP(p []byte) bool {
	ssrc, seq, ok := rtpHeader(p)
	if !ok {
		// A single non-RTP packet does not undo the evidence so far -
		// RTCP and STUN keepalives are interleaved with media on the same
		// 5-tuple throughout a call - but it does not add to it either.
		return false
	}

	if f.rtpRun > 0 && ssrc == f.rtpSSRC && seqPlausible(f.rtpSeq, seq) {
		f.rtpRun++
	} else {
		f.rtpSSRC, f.rtpRun = ssrc, 1
	}
	f.rtpSeq = seq
	return f.rtpRun >= rtpConfirmRun
}

// seqPlausible reports whether one sequence number could follow another in
// the same stream, allowing for reordering, loss, and the 16-bit wrap that
// happens every 65536 packets - about twenty minutes of audio.
func seqPlausible(prev, next uint16) bool {
	return uint16(next-prev) < rtpSeqWindow || uint16(prev-next) < rtpSeqWindow
}
