package relay

import (
	"testing"

	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

// These benchmarks measure the daemon's per-packet processing cost with no
// network at all - pure local CPU, zero WAN data. They isolate the work the
// data path does per packet (header build, dedup, parse, measurement) from
// the syscalls, so a throughput ceiling reached with idle CPU can be pinned
// to processing/locking vs I/O.

var benchPayload = make([]byte, 1300)

func BenchmarkStamp(b *testing.B) {
	s := newTestSession()
	s.registerPath(0)
	scratch := make([]byte, 0, bufSize+maxHeaderLen)
	b.SetBytes(int64(len(benchPayload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.stamp(0, uint32(i), protocol.ClassBulk, benchPayload, scratch)
	}
}

func BenchmarkDeliver(b *testing.B) {
	s := newTestSession()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.deliver(uint32(i))
	}
}

func BenchmarkParse(b *testing.B) {
	s := newTestSession()
	s.registerPath(0)
	scratch := make([]byte, 0, bufSize+maxHeaderLen)
	pkt := s.stamp(0, 1, protocol.ClassBulk, benchPayload, scratch)
	b.SetBytes(int64(len(pkt)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = protocol.Parse(pkt, nil)
	}
}

// The receive hot path a download packet takes: parse, observe, dedup.
func BenchmarkRecvPath(b *testing.B) {
	s := newTestSession()
	s.registerPath(0)
	scratch := make([]byte, 0, bufSize+maxHeaderLen)
	pkt := s.stamp(0, 1, protocol.ClassBulk, benchPayload, scratch)
	b.SetBytes(int64(len(pkt)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h, _, _, err := protocol.Parse(pkt, nil)
		if err != nil {
			b.Fatal(err)
		}
		h.GlobalSeq = uint32(i)
		s.observe(&h, len(pkt))
		s.deliver(uint32(i))
	}
}
