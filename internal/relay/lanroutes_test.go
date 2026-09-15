package relay

import (
	"net/netip"
	"testing"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/lan"
	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

func prefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, p := range s {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

// fakeApplier records what home was asked to route and refuses anything
// overlapping home's pretend LAN, the way the real guard does.
type fakeApplier struct {
	calls [][]netip.Prefix
}

func (f *fakeApplier) apply(set []netip.Prefix) []lan.RouteDecision {
	f.calls = append(f.calls, set)
	return lan.Screen(set, prefixes("10.10.10.0/24"))
}

// The whole exchange: the vehicle sends its LANs, home routes the ones its
// guard allows, and the acknowledgement tells the vehicle which those were.
func TestLANRoutesReachHomeAndReportWhatWasRouted(t *testing.T) {
	vehicle := newSession(nil, "rv", roleInitiator)
	home := newSession(nil, "home", roleResponder)
	fa := &fakeApplier{}
	home.setLANApplier(fa.apply, nil)

	vehicle.setLocalLANRoutes(prefixes("10.0.1.0/24", "10.0.0.0/24", "10.10.10.0/24"))
	now := vehicle.elapsed()
	payload := vehicle.lanRoutesDue(now)
	if payload == nil {
		t.Fatal("a new set is not due")
	}

	// It must survive a real header, encoded at the oldest version: it is
	// sent regardless of what the peer speaks.
	wire := vehicle.build(protocol.TypeLANRoutes, 0, vehicle.nextGlobalSeq(), payload, nil)
	h, body, _, err := protocol.Parse(wire, nil)
	if err != nil || h.Type != protocol.TypeLANRoutes {
		t.Fatalf("parse: type %d, %v", h.Type, err)
	}
	ack := home.receiveLANRoutes(body)
	if len(fa.calls) != 1 || len(fa.calls[0]) != 3 {
		t.Fatalf("home applied %v, want one call with all three subnets", fa.calls)
	}
	vehicle.noteLANRoutesAck(ack)

	vehicle.mu.Lock()
	got := vehicle.lanRoutesSnapshotLocked()
	vehicle.mu.Unlock()
	want := map[string]bool{"10.0.0.0/24": true, "10.0.1.0/24": true, "10.10.10.0/24": false}
	if len(got) != 3 {
		t.Fatalf("snapshot has %d subnets, want 3", len(got))
	}
	for _, r := range got {
		if !r.Acknowledged || r.Routed != want[r.Subnet] {
			t.Errorf("%s: acknowledged %v routed %v, want acknowledged and routed %v", r.Subnet, r.Acknowledged, r.Routed, want[r.Subnet])
		}
	}
	if vehicle.lanRoutesDue(now+time.Hour) != nil {
		t.Error("still sending after home acknowledged")
	}

	// A repeat is answered but not re-applied.
	if home.receiveLANRoutes(body) == nil || len(fa.calls) != 1 {
		t.Errorf("a repeated set was applied again (%d calls)", len(fa.calls))
	}

	// The same subnets in another order are the same set.
	vehicle.setLocalLANRoutes(prefixes("10.10.10.0/24", "10.0.0.0/24", "10.0.1.0/24"))
	if vehicle.lanRoutesDue(now+2*time.Hour) != nil {
		t.Error("a reordered but identical set was sent again")
	}
}

// A home too old to answer is never told the version it would need, so the
// vehicle cannot tell it from a lost acknowledgement. It backs off instead of
// repeating once a second forever.
func TestLANRoutesBackOffWhileUnanswered(t *testing.T) {
	vehicle := newSession(nil, "rv", roleInitiator)
	vehicle.setLocalLANRoutes(prefixes("10.0.0.0/24"))

	now := vehicle.elapsed()
	var sent []time.Duration
	for t0 := now; t0 < now+10*time.Minute; t0 += 100 * time.Millisecond {
		if vehicle.lanRoutesDue(t0) != nil {
			sent = append(sent, t0-now)
		}
	}
	// 0, 1, 3, 7, 15, 31, 63 s, then once a minute: 6 before a minute of
	// backoff, then about 9 more across the rest of the ten minutes.
	if len(sent) < 10 || len(sent) > 20 {
		t.Fatalf("sent %d copies in ten minutes: %v", len(sent), sent)
	}
	for i := 2; i < len(sent); i++ {
		gap := sent[i] - sent[i-1]
		if gap > lanRoutesResendMax+time.Second {
			t.Errorf("gap %d is %v, beyond the %v ceiling", i, gap, lanRoutesResendMax)
		}
		if gap < sent[i-1]-sent[i-2] && gap < lanRoutesResendMax {
			t.Errorf("gap %d shrank to %v before reaching the ceiling", i, gap)
		}
	}
}

// A home that restarts may hold an older set from disk, so the current one is
// sent again, promptly.
func TestPeerRestartResendsLANRoutes(t *testing.T) {
	vehicle := newSession(nil, "rv", roleInitiator)
	home := newSession(nil, "home", roleResponder)
	home.setLANApplier((&fakeApplier{}).apply, nil)
	vehicle.setLocalLANRoutes(prefixes("10.0.0.0/24"))
	vehicle.noteLANRoutesAck(home.receiveLANRoutes(vehicle.lanRoutesDue(vehicle.elapsed())))

	arrive := func(sendTS uint32) {
		h := protocol.Header{Type: protocol.TypeReport, PathID: 0, SendTS: sendTS}
		vehicle.observe(&h, 40)
	}
	nowTS := uint32(time.Since(vehicle.start).Microseconds())
	arrive(nowTS)
	arrive(nowTS + 1000)
	if vehicle.lanRoutesDue(vehicle.elapsed()+time.Hour) != nil {
		t.Fatal("resent with no restart")
	}
	arrive(nowTS - uint32(10*time.Minute/time.Microsecond))
	if vehicle.lanRoutesDue(vehicle.elapsed()+2*time.Second) == nil {
		t.Error("not resent after home restarted")
	}
}

// Home restored from disk holds the set already, so the vehicle sending the
// same one after a home restart is acknowledged without touching routes.
func TestRestoredLANRoutesAreNotReapplied(t *testing.T) {
	vehicle := newSession(nil, "rv", roleInitiator)
	home := newSession(nil, "home", roleResponder)
	fa := &fakeApplier{}
	set := prefixes("10.0.0.0/24", "10.0.1.0/24")
	home.setLANApplier(fa.apply, lan.Screen(set, nil))

	vehicle.setLocalLANRoutes(set)
	ack := home.receiveLANRoutes(vehicle.lanRoutesDue(vehicle.elapsed()))
	if len(fa.calls) != 0 {
		t.Errorf("home re-applied a set it restored from disk")
	}
	vehicle.noteLANRoutesAck(ack)
	vehicle.mu.Lock()
	defer vehicle.mu.Unlock()
	for _, r := range vehicle.lanRoutesSnapshotLocked() {
		if !r.Routed {
			t.Errorf("%s not reported routed", r.Subnet)
		}
	}
}

// A home not running on a TUN has nothing to route into, and says so.
func TestLANRoutesWithoutApplierRouteNothing(t *testing.T) {
	vehicle := newSession(nil, "rv", roleInitiator)
	home := newSession(nil, "home", roleResponder)
	vehicle.setLocalLANRoutes(prefixes("10.0.0.0/24"))
	vehicle.noteLANRoutesAck(home.receiveLANRoutes(vehicle.lanRoutesDue(vehicle.elapsed())))
	vehicle.mu.Lock()
	defer vehicle.mu.Unlock()
	got := vehicle.lanRoutesSnapshotLocked()
	if len(got) != 1 || !got[0].Acknowledged || got[0].Routed {
		t.Errorf("got %+v, want acknowledged but not routed", got)
	}
}
