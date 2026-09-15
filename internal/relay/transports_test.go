package relay

import (
	"net/netip"
	"testing"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
	"github.com/anthonysecco/OpenMultiPath/internal/wan"
)

func transport(id uint8, k byte, addr, isp string) protocol.Transport {
	var key [32]byte
	for i := range key {
		key[i] = k
	}
	return protocol.Transport{PathID: id, PublicKey: key, Addr: netip.MustParseAddr(addr), ISP: isp}
}

// fakePeers is home's wgm holding the vehicle's first two transports.
type fakePeers struct{ calls int }

func (f *fakePeers) apply(list []protocol.Transport) []wan.PeerDecision {
	f.calls++
	existing := []wan.Peer{
		{Key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.20.1.2/32")}},
		{Key: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.20.1.3/32")}},
	}
	return wan.ScreenPeers(list, existing, netip.MustParsePrefix("10.20.1.1/24"))
}

// A third link: home adds the peer it lacks, refuses one that collides, and
// the vehicle learns which is which - with its list built in whatever order a
// map gave it.
func TestTransportsReachHomeAndReportPeers(t *testing.T) {
	vehicle := newSession(nil, "rv", roleInitiator)
	home := newSession(nil, "home", roleResponder)
	fp := &fakePeers{}
	home.setTransportsApplier(fp.apply)

	vehicle.setLocalTransports([]protocol.Transport{
		transport(3, 4, "10.20.1.3", ""), // collides with path 1's peer
		transport(2, 3, "10.20.1.4", "T-Mobile"),
		transport(0, 1, "10.20.1.2", "AT&T"),
		transport(1, 2, "10.20.1.3", "Starlink"),
	})
	now := vehicle.elapsed()
	payload := vehicle.transportsDue(now)
	wire := vehicle.build(protocol.TypeTransports, 0, vehicle.nextGlobalSeq(), payload, nil)
	h, body, _, err := protocol.Parse(wire, nil)
	if err != nil || h.Type != protocol.TypeTransports {
		t.Fatalf("parse: %d %v", h.Type, err)
	}
	vehicle.noteTransportsAck(home.receiveTransports(body))

	vehicle.mu.Lock()
	got := vehicle.transportsSnapshotLocked()
	vehicle.mu.Unlock()
	want := map[uint8]bool{0: true, 1: true, 2: true, 3: false}
	for _, p := range got {
		if !p.Acknowledged || p.Peered != want[p.PathID] {
			t.Errorf("path %d: acknowledged %v peered %v, want peered %v", p.PathID, p.Acknowledged, p.Peered, want[p.PathID])
		}
	}
	home.mu.Lock()
	homeView := home.transportsSnapshotLocked()
	home.mu.Unlock()
	if homeView[3].Peered || homeView[3].Reason == "" {
		t.Errorf("home does not explain the refusal: %+v", homeView[3])
	}

	// Both ends name the paths after their ISP, but a configured label wins.
	c := config.Defaults()
	c.Links = map[string]config.LinkBudget{"wg1": {Label: "My AT&T"}}
	vehicle.nameFor(0, "wg1")
	if l := vehicle.labelFor(c, 0); l != "My AT&T" {
		t.Errorf("configured label lost to the ISP: %q", l)
	}
	if l := vehicle.labelFor(c, 2); l != "T-Mobile" {
		t.Errorf("vehicle path 2 = %q", l)
	}
	if l := home.labelFor(config.Defaults(), 1); l != "Starlink" {
		t.Errorf("home path 1 = %q", l)
	}
	if vehicle.transportsDue(now+time.Hour) != nil {
		t.Error("still sending after home acknowledged")
	}

	// A repeat is answered without adding peers again.
	home.receiveTransports(body)
	if fp.calls != 1 {
		t.Errorf("home applied the same list %d times", fp.calls)
	}
}

// A new ISP name is a changed list, so home hears it.
func TestTransportsResendOnISPChangeAndRestart(t *testing.T) {
	vehicle := newSession(nil, "rv", roleInitiator)
	home := newSession(nil, "home", roleResponder)
	home.setTransportsApplier((&fakePeers{}).apply)
	list := []protocol.Transport{transport(0, 1, "10.20.1.2", "")}
	vehicle.setLocalTransports(list)
	vehicle.noteTransportsAck(home.receiveTransports(vehicle.transportsDue(vehicle.elapsed())))

	list[0].ISP = "AT&T"
	vehicle.setLocalTransports(list)
	if vehicle.transportsDue(vehicle.elapsed()) == nil {
		t.Fatal("a new ISP name was not sent")
	}
	vehicle.noteTransportsAck(home.receiveTransports(vehicle.transportsDue(vehicle.elapsed() + 2*time.Second)))
	if home.ispFor(0) != "AT&T" {
		t.Errorf("home did not learn the name: %q", home.ispFor(0))
	}

	arrive := func(sendTS uint32) {
		h := protocol.Header{Type: protocol.TypeReport, PathID: 0, SendTS: sendTS}
		vehicle.observe(&h, 40)
	}
	nowTS := uint32(time.Since(vehicle.start).Microseconds())
	arrive(nowTS)
	arrive(nowTS + 1000)
	if vehicle.transportsDue(vehicle.elapsed()+time.Hour) != nil {
		t.Fatal("resent with no restart")
	}
	arrive(nowTS - uint32(10*time.Minute/time.Microsecond))
	if vehicle.transportsDue(vehicle.elapsed()+2*time.Second) == nil {
		t.Error("not resent after home restarted")
	}
}
