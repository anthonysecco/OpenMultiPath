package classify

import (
	"encoding/binary"
	"testing"
	"time"
)

// rtpPayload builds a realistic RTP packet: version 2, a dynamic payload
// type, an advancing sequence and a fixed SSRC, padded to size.
func rtpPayload(pt uint8, seq uint16, ssrc uint32, size int) []byte {
	p := make([]byte, size)
	p[0] = 0x80
	p[1] = pt
	binary.BigEndian.PutUint16(p[2:4], seq)
	binary.BigEndian.PutUint32(p[4:8], uint32(seq)*960)
	binary.BigEndian.PutUint32(p[8:12], ssrc)
	return p
}

// quicPayload builds something with a QUIC short-header first byte, which
// is what the bulk side of this actually looks like on the wire.
func quicPayload(size int) []byte {
	p := make([]byte, size)
	p[0] = 0x5f
	return p
}

// The primary use case, as the wire sees it.
//
// CLAUDE.md names the metric that matters: a teleworker on a video call
// while the vehicle is moving. So these are the profiles the classifier is
// actually judged on, and the video ones are why rtp.go exists - they are
// MTU-sized and frame-bursty, and a size-and-gap test calls every one of
// them bulk.
//
// The packet each settles at is as much the point as the verdict. A class
// arrived at at packet 24 is a class arrived at half a second into a call,
// and the first half second of a handover is exactly when it is needed.
func TestRealWorldConferencingProfiles(t *testing.T) {
	type profile struct {
		name    string
		size    int
		rtp     bool
		pt      uint8
		gap     func(i int) time.Duration
		packets int
		want    string
	}
	profiles := []profile{
		{"opus audio 20ms", 180, true, 111, func(int) time.Duration { return 20 * time.Millisecond }, 60, "realtime"},
		{"opus audio, jittery", 180, true, 111, func(i int) time.Duration { return time.Duration(15+i%12) * time.Millisecond }, 60, "realtime"},
		{"720p video 30fps", 1150, true, 96, func(i int) time.Duration {
			if i%8 == 0 {
				return 33 * time.Millisecond
			}
			return 200 * time.Microsecond
		}, 60, "realtime"},
		{"1080p video 30fps", 1350, true, 96, func(i int) time.Duration {
			if i%14 == 0 {
				return 33 * time.Millisecond
			}
			return 150 * time.Microsecond
		}, 60, "realtime"},
		{"screen share", 1300, true, 98, func(i int) time.Duration {
			if i%20 == 0 {
				return 100 * time.Millisecond
			}
			return 100 * time.Microsecond
		}, 60, "realtime"},
		{"QUIC bulk download", 1350, false, 0, func(i int) time.Duration {
			if i%10 == 0 {
				return 40 * time.Millisecond
			}
			return 100 * time.Microsecond
		}, 60, "bulk"},
		{"QUIC small/acks", 90, false, 0, func(i int) time.Duration { return time.Duration(3+i%40) * time.Millisecond }, 60, "bulk"},
	}

	for _, p := range profiles {
		c, clk := testClassifier(t)
		var got uint8
		var at int
		for i := 0; i < p.packets; i++ {
			clk.add(p.gap(i))
			var payload []byte
			if p.rtp {
				payload = rtpPayload(p.pt, uint16(i), 0xdeadbe00, p.size)
			} else {
				payload = quicPayload(p.size)
			}
			got = c.Classify(udp4("10.20.0.2", 40000, "5.6.7.8", 8801, payload, p.size))
			if at == 0 && className(got) == p.want {
				at = i + 1
			}
		}
		status := "ok"
		if className(got) != p.want {
			status = "WRONG"
			t.Errorf("%s classified %s, want %s", p.name, className(got), p.want)
		}
		t.Logf("  %-22s -> %-8s (settled at packet %d) %s", p.name, className(got), at, status)
	}
}

// The case that motivates RTP detection: a daemon that started in the
// middle of an existing call never saw the ICE handshake, so STUN cannot
// help it. Video still has to be identified.
func TestVideoIsCaughtWithoutEverSeeingSTUN(t *testing.T) {
	c, clk := testClassifier(t)
	var got uint8
	for i := 0; i < 10; i++ {
		clk.add(200 * time.Microsecond)
		got = c.Classify(udp4("10.20.0.2", 50000, "5.6.7.8", 3478,
			rtpPayload(96, uint16(i), 0x11223344, 1350), 1350))
		if className(got) == "realtime" {
			t.Logf("  mid-call video, no STUN ever seen -> realtime at packet %d", i+1)
			return
		}
	}
	t.Errorf("mid-call video was never identified; ended as %s", className(got))
}
