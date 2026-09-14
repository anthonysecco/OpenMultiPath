package relay

import (
	"testing"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

// exchange carries one packet from a sender session to a receiver session the
// way the data path does, and reports what the receiver delivered.
func exchange(t *testing.T, from, to *session, pkt []byte, delivered *[][]byte) {
	t.Helper()
	h, payload, ver, err := protocol.Parse(pkt, to.authKey)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	to.notePeerVersion(ver)
	to.observe(&h, len(pkt))
	if h.Type != protocol.TypeData {
		return
	}
	if err := to.deliverData(&h, payload, func(p []byte) error {
		*delivered = append(*delivered, append([]byte(nil), p...))
		return nil
	}); err != nil {
		t.Fatalf("deliver: %v", err)
	}
}

// Two current builds reach the current version from a cold start, and bulk
// then carries the flow sequence while everything else does not.
func TestTwoVersionThreeSessionsNegotiateAndStampFlows(t *testing.T) {
	a, b := newTestSession(), newTestSession()
	var got [][]byte
	exchange(t, a, b, a.stamp(0, a.nextGlobalSeq(), protocol.ClassUnknown, []byte("hello"), nil), &got)
	exchange(t, b, a, b.stamp(0, b.nextGlobalSeq(), protocol.ClassUnknown, []byte("hello"), nil), &got)
	if a.emitVersion() != protocol.Version || b.emitVersion() != protocol.Version {
		t.Fatalf("negotiated %d and %d, want %d", a.emitVersion(), b.emitVersion(), protocol.Version)
	}

	flow := uint32(0xABCDE)
	tag := a.nextFlowTag(flow)
	h, _, _, err := protocol.Parse(a.stampFlow(1, a.nextGlobalSeq(), protocol.ClassBulk, tag, []byte("bulk"), nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !h.HasFlow || h.FlowBucket != uint16(flow%protocol.FlowBuckets) || h.FlowSeq != tag.seq {
		t.Errorf("bulk header %+v, want the flow tag %+v", h, tag)
	}
	h, _, _, err = protocol.Parse(a.stampFlow(1, a.nextGlobalSeq(), protocol.ClassTransactional, flowTag{}, []byte("page"), nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if h.HasFlow {
		t.Error("a transactional packet carried a flow sequence")
	}
}

// Flow sequences count per bucket, one per packet.
func TestFlowTagsCountPerBucket(t *testing.T) {
	s := newTestSession()
	for i := uint32(0); i < 3; i++ {
		if tag := s.nextFlowTag(10); tag.seq != i {
			t.Errorf("packet %d of flow 10 got sequence %d", i, tag.seq)
		}
	}
	if tag := s.nextFlowTag(11); tag.seq != 0 {
		t.Errorf("first packet of another flow got sequence %d, want 0", tag.seq)
	}
	if tag := s.nextFlowTag(10 + protocol.FlowBuckets); tag.seq != 3 {
		t.Errorf("a flow hashing to the same bucket got %d, want to share its sequence (3)", tag.seq)
	}
}

// End to end through two sessions: bulk spread across two paths and arriving
// out of order is delivered in order.
func TestSpreadBulkIsDeliveredInOrder(t *testing.T) {
	a, b := newTestSession(), newTestSession()
	var got [][]byte
	b.reseq = newResequencer(func(p []byte) error {
		got = append(got, append([]byte(nil), p...))
		return nil
	}, b.elapsed)
	// Negotiate.
	exchange(t, a, b, a.stamp(0, a.nextGlobalSeq(), protocol.ClassUnknown, nil, nil), &got)
	exchange(t, b, a, b.stamp(0, b.nextGlobalSeq(), protocol.ClassUnknown, nil, nil), &got)
	got = nil

	pkts := make([][]byte, 7)
	for i := range pkts {
		path := uint8(i % 2)
		pkts[i] = a.stampFlow(path, a.nextGlobalSeq(), protocol.ClassBulk, a.nextFlowTag(42), []byte{byte('0' + i)}, nil)
	}
	// The flow's first packet arrives, then path 1 (odd packets) runs ahead
	// of path 0.
	for _, i := range []int{0, 1, 3, 5, 2, 4, 6} {
		exchange(t, a, b, pkts[i], &got)
	}
	if len(got) != 7 {
		t.Fatalf("delivered %d packets, want 7", len(got))
	}
	for i, p := range got {
		if p[0] != byte('0'+i) {
			t.Fatalf("delivered %q, want 0 through 5 in order", got)
		}
	}
}

// A duplicated real-time packet is still delivered once, and never waits in
// the resequencer.
func TestRealtimeBypassesTheResequencer(t *testing.T) {
	a, b := newTestSession(), newTestSession()
	var got [][]byte
	b.reseq = newResequencer(func(p []byte) error { t.Fatal("real-time went through the resequencer"); return nil }, b.elapsed)
	exchange(t, a, b, a.stamp(0, a.nextGlobalSeq(), protocol.ClassUnknown, nil, nil), &got)
	exchange(t, b, a, b.stamp(0, b.nextGlobalSeq(), protocol.ClassUnknown, nil, nil), &got)
	got = nil

	seq := a.nextGlobalSeq()
	exchange(t, a, b, a.stampFlow(0, seq, protocol.ClassRealtime, flowTag{}, []byte("rtp"), nil), &got)
	exchange(t, a, b, a.stampFlow(1, seq, protocol.ClassRealtime, flowTag{}, []byte("rtp"), nil), &got)
	if len(got) != 1 {
		t.Errorf("delivered %d copies of one real-time packet, want 1", len(got))
	}
}

// The sender paces bulk on what we report, so while spread bulk is arriving
// a path must report at the fast cadence even though it is busy - which is
// exactly when the ordinary idle-only rule would never let it report.
func TestSpreadBulkTriggersFastReports(t *testing.T) {
	a, b := newTestSession(), newTestSession()
	var got [][]byte
	exchange(t, a, b, a.stamp(0, a.nextGlobalSeq(), protocol.ClassUnknown, nil, nil), &got)
	exchange(t, b, a, b.stamp(0, b.nextGlobalSeq(), protocol.ClassUnknown, nil, nil), &got)

	if b.fastReportDue(0) {
		t.Fatal("fast reports due before any spread bulk arrived")
	}
	exchange(t, a, b, a.stampFlow(0, a.nextGlobalSeq(), protocol.ClassBulk, a.nextFlowTag(1), []byte("x"), nil), &got)
	time.Sleep(b.cfg.Get().CascadeReportInterval() + 10*time.Millisecond)
	if !b.fastReportDue(0) {
		t.Fatal("no fast report due on a path carrying spread bulk")
	}

	rep := b.buildReportWith(0, nil, true)
	h, _, _, err := protocol.Parse(rep, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Reports) == 0 {
		t.Fatal("fast report carried no path reports")
	}
	if b.fastReportDue(0) {
		t.Error("fast report still due immediately after sending one")
	}
}

// Against a version 2 peer there is no fast cadence to speak of: it cannot
// read the figures, and it is not spreading anything.
func TestNoFastReportsTowardAVersionTwoPeer(t *testing.T) {
	b := newTestSession()
	b.notePeerVersion(2)
	b.mu.Lock()
	b.pathLocked(0).bulkRxAt = b.elapsed()
	b.mu.Unlock()
	time.Sleep(b.cfg.Get().CascadeReportInterval() + 10*time.Millisecond)
	if b.fastReportDue(0) {
		t.Error("fast report due toward a version 2 peer")
	}
}

// shortRxKbps still follows the last second even though its byte-rate
// bucket now also stands in for what standing-queue/short-loss used to
// track before D-055 removed the controller that paced on them.
func TestShortRxKbpsFollowsTheLastSecond(t *testing.T) {
	var st pathStats
	now := time.Duration(0)
	for i := 0; i < 90; i++ {
		now += 10 * time.Millisecond
		st.observeTransit(1000, now)
		st.noteBytes(1250) // 1000 bytes/10ms -> 1 Mbps -ish, in wire bytes
	}
	if kbps := st.shortRxKbps(now); kbps < 500 {
		t.Errorf("short rx %.0f kbps while receiving steadily, want it visible", kbps)
	}
	for i := 0; i < 150; i++ {
		now += 10 * time.Millisecond
		st.observeTransit(1000, now)
	}
	if kbps := st.shortRxKbps(now); kbps != 0 {
		t.Errorf("short rx %.0f kbps 1.5 s after the last byte, want 0", kbps)
	}
}
