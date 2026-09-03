package relay

import (
	"net"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
)

func cidr(t *testing.T, s string) net.Addr {
	t.Helper()
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	n.IP = ip
	return n
}

// A cellular interface carries a link-local address in the window between
// the link coming up and DHCP finishing. Binding to it would give a path
// that looks up and delivers nothing.
func TestPickIPv4SkipsUnusableAddresses(t *testing.T) {
	for _, tc := range []struct {
		name  string
		addrs []string
		want  string
	}{
		{"global", []string{"100.110.247.30/10"}, "100.110.247.30"},
		{"skips link-local", []string{"169.254.7.1/16", "192.168.225.3/22"}, "192.168.225.3"},
		{"skips loopback", []string{"127.0.0.1/8", "10.0.0.1/24"}, "10.0.0.1"},
		{"skips v6", []string{"2605:59c0:2200:fbaf::1/64", "10.0.0.1/24"}, "10.0.0.1"},
		{"nothing usable", []string{"169.254.7.1/16", "2605:59c0::1/64"}, ""},
		{"none at all", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addrs := make([]net.Addr, len(tc.addrs))
			for i, a := range tc.addrs {
				addrs[i] = cidr(t, a)
			}
			got, ok := pickIPv4(addrs)
			if tc.want == "" {
				if ok {
					t.Fatalf("expected no usable address, got %s", got)
				}
				return
			}
			if !ok || got != tc.want {
				t.Fatalf("got %q (ok=%v), want %q", got, ok, tc.want)
			}
		})
	}
}

// A link that has not come up yet is a path that is down, not an error.
func TestLocalIPMissingInterface(t *testing.T) {
	spec := pathSpec{id: 0, name: "definitely-not-an-interface0"}
	if _, err := spec.localIP(); err == nil {
		t.Fatal("expected an error for an absent interface")
	} else if !strings.Contains(err.Error(), "not present") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

// Pinning says which address to use, not that the link is up. A pinned
// address that has gone away has to read as down, or the daemon would keep
// a socket bound to an address that will never deliver again.
func TestLocalIPPinnedAddressAbsent(t *testing.T) {
	spec := pathSpec{id: 0, name: "lo", pin: "203.0.113.99"}
	if _, err := spec.localIP(); err == nil {
		t.Fatal("expected an error for a pinned address that is not configured")
	}
}

// The whole point of the reconcile loop: a configured link that is not
// there must leave the daemon running with that path simply down.
func TestReconcileWithNoLinksPresent(t *testing.T) {
	sess := newSession(config.NewHolder(config.Defaults()), "test", roleInitiator)
	sess.registerPath(0)

	ps := newPathSet(
		[]pathSpec{{id: 0, name: "definitely-not-an-interface0"}},
		sess,
		&net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 48219},
		func(uint8, []byte) { t.Error("nothing should have arrived") },
	)

	ps.reconcile()
	if got := ps.active(); len(got) != 0 {
		t.Fatalf("expected no bound paths, got %v", got)
	}

	// Sending down a path that is down is the expected state of a link in
	// a dead zone, not a failure.
	ps.send(0, []byte("dropped on the floor"))

	snap := sess.snapshot(0)
	if len(snap.Paths) != 1 {
		t.Fatalf("expected the path to still be listed, got %d", len(snap.Paths))
	}
	if snap.Paths[0].Bound {
		t.Error("path reported as bound when its interface does not exist")
	}
	if !snap.ManagesPaths {
		t.Error("the initiator owns its sockets and should say so")
	}
}

// Drops are what the flap penalty will be built on, so they must count
// transitions rather than calls.
func TestDropsCountTransitions(t *testing.T) {
	sess := newSession(config.NewHolder(config.Defaults()), "test", roleInitiator)

	sess.setBound(0, "192.168.225.3")
	if got := sess.snapshot(0).Paths[0].Drops; got != 0 {
		t.Fatalf("coming up is not a drop, got %d", got)
	}

	sess.setUnbound(0)
	sess.setUnbound(0) // already down; must not count again
	if got := sess.snapshot(0).Paths[0].Drops; got != 1 {
		t.Fatalf("drops = %d, want 1", got)
	}

	// An address change is a rebind, and it is a real interruption.
	sess.setBound(0, "192.168.225.9")
	sess.setUnbound(0)
	sess.setBound(0, "192.168.226.4")

	p := sess.snapshot(0).Paths[0]
	if p.Drops != 2 {
		t.Fatalf("drops = %d, want 2", p.Drops)
	}
	if !p.Bound || p.Local != "192.168.226.4" {
		t.Fatalf("expected bound to the new address, got bound=%v local=%s", p.Bound, p.Local)
	}
}

// The responder learns its paths from what arrives and owns no sockets, so
// it must not report every healthy path as unbound.
func TestResponderReportsNoBindState(t *testing.T) {
	sess := newSession(config.NewHolder(config.Defaults()), "test", roleResponder)
	sess.registerPath(0)

	snap := sess.snapshot(0)
	if snap.ManagesPaths {
		t.Error("the responder does not own its sockets")
	}
	if snap.Paths[0].Bound || snap.Paths[0].Local != "" {
		t.Error("bind state leaked into a responder snapshot")
	}
}

// A D-020 misconfiguration reaches the operator as ENOKEY from the kernel,
// worded "required key not available", which reads as a crypto failure and
// is really -remote naming an address no peer routes. The hint is the only
// thing standing between that and a long detour, so it is worth a test.
func TestMisroutedHintOnlyForENOKEY(t *testing.T) {
	remote := &net.UDPAddr{IP: net.IPv4(162, 231, 243, 253), Port: 48219}
	ps := newPathSet([]pathSpec{{id: 0, name: "wg1"}}, nil, remote, func(uint8, []byte) {})

	got := ps.misroutedHint(0, &os.SyscallError{Syscall: "sendto", Err: syscall.ENOKEY})
	if !strings.Contains(got, "wg1") || !strings.Contains(got, "162.231.243.253") {
		t.Errorf("hint should name the interface and the destination, got %q", got)
	}
	if !strings.Contains(got, "tunnel address") {
		t.Errorf("hint should point at -remote, got %q", got)
	}

	// Every other write failure is an ordinary dead-zone state and must
	// not be dressed up as a configuration error.
	if got := ps.misroutedHint(0, syscall.ENETUNREACH); got != "" {
		t.Errorf("unrelated errors should get no hint, got %q", got)
	}
}
