package relay

import (
	"testing"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/linkspeed"
	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

// linkSpeedPair is a vehicle and a home session that have negotiated version
// 4, with the vehicle's paths named as its -paths flag would name them.
func linkSpeedPair() (vehicle, home *session) {
	vehicle = newSession(nil, "rv", roleInitiator)
	home = newSession(nil, "home", roleResponder)
	vehicle.nameFor(0, "wg1")
	vehicle.nameFor(1, "wg2")
	vehicle.notePeerVersion(protocol.Version)
	home.notePeerVersion(protocol.Version)
	return vehicle, home
}

func measured(links map[string]linkspeed.Measurement) linkspeed.File {
	return linkspeed.File{Links: links}
}

// The whole exchange: the vehicle shapes to its upload, sends the set until
// home answers, home shapes to the download, and once acknowledged nothing
// more is sent.
func TestLinkSpeedsReachHomeAndAreAcknowledged(t *testing.T) {
	vehicle, home := linkSpeedPair()
	vehicle.setLocalSpeeds(vehicle.speedsFromFile(measured(map[string]linkspeed.Measurement{
		"wg1": {UpKbps: 10_000, DownKbps: 50_000, MeasuredUnix: 1_790_000_000},
	})))

	vehicle.mu.Lock()
	up0, up1 := vehicle.shapedKbpsLocked(0), vehicle.shapedKbpsLocked(1)
	vehicle.mu.Unlock()
	if up0 != 9_500 || up1 != 0 {
		t.Errorf("vehicle shaped path 0 to %.0f and path 1 to %.0f, want 9500 and unshaped", up0, up1)
	}

	now := vehicle.elapsed()
	payload := vehicle.linkSpeedDue(now)
	if payload == nil {
		t.Fatal("a new set is not due to be sent")
	}
	if vehicle.linkSpeedDue(now+linkSpeedResend/2) != nil {
		t.Error("resent before the resend interval")
	}

	// It rides a real packet, so check it survives the header.
	wire := vehicle.build(protocol.TypeLinkSpeed, 0, vehicle.nextGlobalSeq(), payload, nil)
	h, body, _, err := protocol.Parse(wire, nil)
	if err != nil || h.Type != protocol.TypeLinkSpeed {
		t.Fatalf("parse: type %d, %v", h.Type, err)
	}
	ack := home.receiveLinkSpeeds(body)
	if ack == nil {
		t.Fatal("home did not acknowledge")
	}
	home.mu.Lock()
	down0 := home.shapedKbpsLocked(0)
	home.mu.Unlock()
	if down0 != 47_500 {
		t.Errorf("home shaped path 0 to %.0f, want 47500 (95%% of the download)", down0)
	}

	// Unacknowledged, it is repeated.
	if vehicle.linkSpeedDue(now+linkSpeedResend) == nil {
		t.Error("not resent after the interval with no acknowledgement")
	}
	vehicle.noteLinkSpeedAck(ack)
	if vehicle.linkSpeedDue(now+10*linkSpeedResend) != nil {
		t.Error("still sending after home acknowledged")
	}

	// The same measurements again change nothing and send nothing.
	vehicle.setLocalSpeeds(vehicle.speedsFromFile(measured(map[string]linkspeed.Measurement{
		"wg1": {UpKbps: 10_000, DownKbps: 50_000, MeasuredUnix: 1_790_000_000},
	})))
	if vehicle.linkSpeedDue(now+20*linkSpeedResend) != nil {
		t.Error("an unchanged set was sent again")
	}
}

// Only a change is sent, and a cleared measurement is a change: home must
// stop shaping a link the vehicle no longer has a figure for.
func TestClearedLinkSpeedUnshapesHome(t *testing.T) {
	vehicle, home := linkSpeedPair()
	vehicle.setLocalSpeeds(vehicle.speedsFromFile(measured(map[string]linkspeed.Measurement{
		"wg2": {UpKbps: 3_000, DownKbps: 20_000, MeasuredUnix: 1},
	})))
	vehicle.noteLinkSpeedAck(home.receiveLinkSpeeds(vehicle.linkSpeedDue(vehicle.elapsed())))

	vehicle.setLocalSpeeds(vehicle.speedsFromFile(measured(nil)))
	payload := vehicle.linkSpeedDue(vehicle.elapsed())
	if payload == nil {
		t.Fatal("clearing the measurement is not sent")
	}
	home.receiveLinkSpeeds(payload)
	home.mu.Lock()
	defer home.mu.Unlock()
	if got := home.shapedKbpsLocked(1); got != 0 {
		t.Errorf("home still shapes path 1 to %.0f after the vehicle cleared it", got)
	}
}

// A peer that restarts has forgotten the set, so it is sent again - found by
// the same restart detection that resets sequence tracking.
func TestPeerRestartResendsLinkSpeeds(t *testing.T) {
	vehicle, home := linkSpeedPair()
	vehicle.setLocalSpeeds(vehicle.speedsFromFile(measured(map[string]linkspeed.Measurement{
		"wg1": {UpKbps: 10_000, DownKbps: 50_000, MeasuredUnix: 1},
	})))
	vehicle.noteLinkSpeedAck(home.receiveLinkSpeeds(vehicle.linkSpeedDue(vehicle.elapsed())))

	arrive := func(sendTS uint32) {
		h := protocol.Header{Type: protocol.TypeReport, PathID: 0, SendTS: sendTS}
		vehicle.observe(&h, 40)
	}
	nowTS := uint32(time.Since(vehicle.start).Microseconds())
	arrive(nowTS)
	arrive(nowTS + 1000)
	if vehicle.linkSpeedDue(vehicle.elapsed()+10*linkSpeedResend) != nil {
		t.Fatal("resent with no restart")
	}
	arrive(nowTS - uint32(10*time.Minute/time.Microsecond)) // home came back with a new clock
	if vehicle.linkSpeedDue(vehicle.elapsed()+20*linkSpeedResend) == nil {
		t.Error("not resent after home restarted")
	}
}

// A peer that cannot answer is never sent the set: it would be repeated forever.
func TestLinkSpeedsNotSentToAnOlderPeer(t *testing.T) {
	vehicle := newSession(nil, "rv", roleInitiator)
	vehicle.nameFor(0, "wg1")
	vehicle.notePeerVersion(3)
	vehicle.setLocalSpeeds(vehicle.speedsFromFile(measured(map[string]linkspeed.Measurement{
		"wg1": {UpKbps: 10_000, MeasuredUnix: 1},
	})))
	if vehicle.linkSpeedDue(vehicle.elapsed()) != nil {
		t.Error("link speeds sent to a version 3 peer")
	}
	// It still shapes its own sends; that needs nothing from home.
	vehicle.mu.Lock()
	defer vehicle.mu.Unlock()
	if got := vehicle.shapedKbpsLocked(0); got != 9_500 {
		t.Errorf("shaped to %.0f, want 9500", got)
	}
}

// The shaper counts what the link carries: above WireGuard a packet costs its
// padding, WireGuard's framing and two UDP/IPv4 headers.
func TestSessionCountsWireGuardOverhead(t *testing.T) {
	s := newSession(nil, "rv", roleInitiator)
	s.setPathWriter(func(uint8, []byte) {}, true)
	if got := s.wireBytes(1200); got != 1292 {
		t.Errorf("wireBytes(1200) through WireGuard = %d, want 1292", got)
	}
	s.setPathWriter(func(uint8, []byte) {}, false)
	if got := s.wireBytes(1200); got != 1228 {
		t.Errorf("wireBytes(1200) direct = %d, want 1228", got)
	}
}

// A path's shaper picks up the speed already held when it is first used, and
// a later set reshapes it.
func TestShapersFollowTheSet(t *testing.T) {
	vehicle, _ := linkSpeedPair()
	vehicle.setPathWriter(func(uint8, []byte) {}, true)
	sh := vehicle.shaperFor(0)
	if sh.kbps() != 0 {
		t.Fatalf("unmeasured path shaped to %.0f", sh.kbps())
	}
	vehicle.setLocalSpeeds(vehicle.speedsFromFile(measured(map[string]linkspeed.Measurement{
		"wg1": {UpKbps: 20_000, MeasuredUnix: 1},
		"wg2": {UpKbps: 4_000, MeasuredUnix: 1},
	})))
	if got := sh.kbps(); got < 18_999 || got > 19_001 {
		t.Errorf("existing shaper at %.0f kbps, want 19000", got)
	}
	if got := vehicle.shaperFor(1).kbps(); got < 3_799 || got > 3_801 {
		t.Errorf("new shaper at %.0f kbps, want 3800", got)
	}
}
