package classify

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
)

// A fake clock, because the behavioural heuristic's entire input is
// inter-packet timing and a test that used the real one would be
// measuring the machine it ran on.
type clock struct{ t time.Time }

func newClock() *clock {
	return &clock{t: time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)}
}
func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

// testClassifier returns a classifier on defaults with a fake clock.
func testClassifier(t *testing.T) (*Classifier, *clock) {
	t.Helper()
	clk := newClock()
	c := New(nil)
	c.now = clk.now
	return c, clk
}

// udp4 builds an IPv4/UDP packet whose total length is size bytes, padding
// the payload out to reach it. A payload longer than size wins; size is a
// floor in that case.
func udp4(srcIP string, sport int, dstIP string, dport int, payload []byte, size int) []byte {
	body := payload
	if n := size - 28; n > len(body) {
		body = append(append([]byte{}, body...), make([]byte, n-len(body))...)
	}
	return ip4(srcIP, dstIP, protoUDP, udpHeader(sport, dport, body))
}

func tcp4(srcIP string, sport int, dstIP string, dport int, size int) []byte {
	body := make([]byte, max(0, size-40))
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], uint16(sport))
	binary.BigEndian.PutUint16(hdr[2:4], uint16(dport))
	hdr[12] = 5 << 4 // data offset: five 32-bit words, no options
	return ip4(srcIP, dstIP, protoTCP, append(hdr, body...))
}

func udpHeader(sport, dport int, body []byte) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:2], uint16(sport))
	binary.BigEndian.PutUint16(h[2:4], uint16(dport))
	binary.BigEndian.PutUint16(h[4:6], uint16(8+len(body)))
	return append(h, body...)
}

func ip4(srcIP, dstIP string, proto uint8, transport []byte) []byte {
	h := make([]byte, 20)
	h[0] = 4<<4 | 5
	binary.BigEndian.PutUint16(h[2:4], uint16(20+len(transport)))
	h[8] = 64
	h[9] = proto
	copy(h[12:16], net.ParseIP(srcIP).To4())
	copy(h[16:20], net.ParseIP(dstIP).To4())
	return append(h, transport...)
}

// stunBinding is a well-formed RFC 5389 binding request with no
// attributes, which is all the classifier looks at.
func stunBinding() []byte {
	p := make([]byte, stunHeaderLen)
	binary.BigEndian.PutUint16(p[0:2], stunMethodBinding)
	binary.BigEndian.PutUint16(p[2:4], 0)
	binary.BigEndian.PutUint32(p[4:8], stunMagicCookie)
	copy(p[8:20], []byte("transaction!"))
	return p
}

func defaults() config.Config { return config.Defaults() }
