package classify

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

// Replay of a real capture taken on the RV's tunnel interface, which
// carries exactly the plaintext inner packets the TUN device will hand the
// classifier once D-020 lands. Synthetic packets only prove the code does
// what its author expected; this proves it against traffic the RV actually
// generated.
//
// Set OMP_PCAP to a raw-IP capture to run it.
func TestReplayRealCapture(t *testing.T) {
	path := os.Getenv("OMP_PCAP")
	if path == "" {
		t.Skip("set OMP_PCAP to a raw-IP capture to replay it")
	}
	pkts, err := readPcap(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	t.Logf("replaying %d packets from %s", len(pkts), path)

	clk := newClock()
	c := New(nil)
	c.now = clk.now

	type stat struct {
		key            FlowKey
		class          uint8
		packets        int
		bytes          int64
		firstDecidedAt int // packet index within the flow when it settled
	}
	flows := map[FlowKey]*stat{}
	var order []FlowKey

	for _, p := range pkts {
		clk.t = p.ts
		class := c.Classify(p.data)

		parsed, ok := parse(p.data)
		if !ok {
			continue
		}
		s := flows[parsed.flow]
		if s == nil {
			s = &stat{key: parsed.flow, firstDecidedAt: -1}
			flows[parsed.flow] = s
			order = append(order, parsed.flow)
		}
		s.packets++
		s.bytes += int64(parsed.size)
		s.class = class
		if class != protocol.ClassUnknown && s.firstDecidedAt < 0 {
			s.firstDecidedAt = s.packets
		}
	}

	sort.Slice(order, func(i, j int) bool {
		return flows[order[i]].packets > flows[order[j]].packets
	})

	byClass := map[uint8]int{}
	bytesByClass := map[uint8]int64{}
	for _, k := range order {
		byClass[flows[k].class]++
		bytesByClass[flows[k].class] += flows[k].bytes
	}

	t.Log("top flows by packet count:")
	for i, k := range order {
		if i >= 14 {
			break
		}
		s := flows[k]
		proto := "udp"
		if k.Proto == protoTCP {
			proto = "tcp"
		}
		t.Logf("  %-9s %-22s <-> %-22s %6d pkts %9d B  mean %4.0f B  decided@%d",
			className(s.class)+"/"+proto,
			fmt.Sprintf("%s:%d", k.A, k.APort),
			fmt.Sprintf("%s:%d", k.B, k.BPort),
			s.packets, s.bytes, float64(s.bytes)/float64(s.packets), s.firstDecidedAt)
	}
	t.Logf("flows: %d realtime, %d bulk, %d unknown (of %d)",
		byClass[protocol.ClassRealtime], byClass[protocol.ClassBulk],
		byClass[protocol.ClassUnknown], len(order))
	t.Logf("bytes: %d realtime, %d bulk, %d unknown",
		bytesByClass[protocol.ClassRealtime], bytesByClass[protocol.ClassBulk],
		bytesByClass[protocol.ClassUnknown])

	// The load-bearing assertion. Nearly every byte in this capture is a
	// bulk download; if a meaningful share of it came out real-time, the
	// heuristic would be duplicating downloads over a metered link, which
	// is precisely the failure D-018 exists to prevent.
	rt, total := bytesByClass[protocol.ClassRealtime], int64(0)
	for _, b := range bytesByClass {
		total += b
	}
	if share := float64(rt) / float64(total) * 100; share > 5 {
		t.Errorf("%.1f%% of captured bytes classified real-time; the capture is almost entirely bulk", share)
	}
}

type rawPacket struct {
	ts   time.Time
	data []byte
}

// readPcap reads a classic libpcap file of raw IP packets. Only the fields
// the replay needs are interpreted: the timestamp, because the behavioural
// heuristic is driven entirely by inter-packet gaps, and the bytes.
func readPcap(path string) ([]rawPacket, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) < 24 {
		return nil, fmt.Errorf("short file")
	}

	var bo binary.ByteOrder = binary.LittleEndian
	nano := false
	switch binary.LittleEndian.Uint32(b[0:4]) {
	case 0xa1b2c3d4:
	case 0xa1b23c4d:
		nano = true
	case 0xd4c3b2a1:
		bo = binary.BigEndian
	case 0x4d3cb2a1:
		bo, nano = binary.BigEndian, true
	default:
		return nil, fmt.Errorf("not a pcap file")
	}
	if lt := bo.Uint32(b[20:24]); lt != 101 {
		return nil, fmt.Errorf("link type %d, want 101 (raw IP)", lt)
	}

	var out []rawPacket
	for off := 24; off+16 <= len(b); {
		sec := bo.Uint32(b[off : off+4])
		frac := bo.Uint32(b[off+4 : off+8])
		incl := int(bo.Uint32(b[off+8 : off+12]))
		orig := int(bo.Uint32(b[off+12 : off+16]))
		off += 16
		if incl < 0 || off+incl > len(b) {
			break
		}
		if incl != orig {
			return nil, fmt.Errorf("capture is truncated (snaplen); packet sizes would be wrong")
		}
		ns := int64(frac) * 1000
		if nano {
			ns = int64(frac)
		}
		out = append(out, rawPacket{ts: time.Unix(int64(sec), ns).UTC(), data: b[off : off+incl]})
		off += incl
	}
	return out, nil
}
