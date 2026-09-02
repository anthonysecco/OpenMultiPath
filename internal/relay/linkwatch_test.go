package relay

import (
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/tun"
)

func requireNetlink(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to create an interface to observe")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("no /dev/net/tun on this machine")
	}
}

// makeLink creates a real interface for the watcher to see, and returns a
// function that removes it.
func makeLink(t *testing.T, name, cidr string) func() {
	t.Helper()
	d, err := tun.Open(tun.Config{Name: name, MTU: 1300, Address: netip.MustParsePrefix(cidr)})
	if err != nil {
		t.Skipf("cannot create %s here: %v", name, err)
	}
	closed := false
	return func() {
		if !closed {
			closed = true
			d.Close()
		}
	}
}

func TestWatcherSeesInterfacesAppearAndDisappear(t *testing.T) {
	requireNetlink(t)
	w, err := watchLinks()
	if err != nil {
		t.Skipf("netlink unavailable: %v", err)
	}
	defer w.Stop()

	drain := func() {
		for {
			select {
			case <-w.C():
			default:
				return
			}
		}
	}
	drain()

	del := makeLink(t, "ompnl0", "10.98.0.1/24")
	select {
	case <-w.C():
	case <-time.After(5 * time.Second):
		del()
		t.Fatal("no event when an interface appeared")
	}

	drain()
	del()
	select {
	case <-w.C():
	case <-time.After(5 * time.Second):
		t.Fatal("no event when an interface disappeared")
	}
}

// A burst of messages must not queue a burst of reconciles. Bringing an
// interface up emits several, and they all mean the same thing.
func TestWatcherCoalescesABurst(t *testing.T) {
	w := &linkWatcher{events: make(chan struct{}, 1)}
	for i := 0; i < 50; i++ {
		w.notify()
	}
	if n := len(w.C()); n != 1 {
		t.Errorf("50 notifications queued %d wakeups, want 1", n)
	}
}

// The point of D-029. A link appearing must be acted on promptly rather
// than at the next backstop sweep, so the test creates one well after the
// initial reconcile and requires the path to bind in a fraction of
// rebindInterval - a margin only an event can meet.
func TestPathBindsFromAnEventNotTheSweep(t *testing.T) {
	requireNetlink(t)

	sess := newSession(nil, "test", roleInitiator)
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	ps := newPathSet([]pathSpec{{id: 0, name: "ompnl1"}}, sess, remote, func(uint8, []byte) {})
	sess.registerPath(0)

	go ps.run()
	time.Sleep(400 * time.Millisecond) // let the initial reconcile pass

	if len(ps.active()) != 0 {
		t.Fatal("path was bound before its interface existed")
	}

	start := time.Now()
	del := makeLink(t, "ompnl1", "10.98.1.1/24")
	defer del()

	deadline := time.Now().Add(rebindInterval + time.Second)
	for len(ps.active()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	took := time.Since(start)

	if len(ps.active()) == 0 {
		t.Fatalf("path never bound, %s after its interface appeared", took)
	}
	// The sweep could not have run yet: run() ticks at rebindInterval from
	// start, and the interface appeared 400ms in. Anything under half an
	// interval had to come from an event.
	if took > rebindInterval/2 {
		t.Errorf("path took %s to bind - that is sweep latency, not event latency;"+
			" D-029 is not fixed", took)
	}
	t.Logf("bound %s after the interface appeared (backstop sweep is %s)", took, rebindInterval)
}

// The other direction, which is the one D-029 actually measured: a link
// going away has to be noticed without waiting out the sweep.
func TestPathDropsFromAnEventNotTheSweep(t *testing.T) {
	requireNetlink(t)

	sess := newSession(nil, "test", roleInitiator)
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	ps := newPathSet([]pathSpec{{id: 0, name: "ompnl2"}}, sess, remote, func(uint8, []byte) {})
	sess.registerPath(0)

	del := makeLink(t, "ompnl2", "10.98.2.1/24")
	go ps.run()

	deadline := time.Now().Add(3 * time.Second)
	for len(ps.active()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(ps.active()) == 0 {
		t.Fatal("path never bound to start with")
	}
	time.Sleep(300 * time.Millisecond) // settle, clear of the next tick

	start := time.Now()
	del()

	deadline = time.Now().Add(rebindInterval + time.Second)
	for len(ps.active()) != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	took := time.Since(start)

	if len(ps.active()) != 0 {
		t.Fatalf("path was still bound %s after its interface went away", took)
	}
	if took > rebindInterval/2 {
		t.Errorf("path took %s to drop - that is sweep latency, and it is the"+
			" three seconds of dead audio D-029 is about", took)
	}
	t.Logf("dropped %s after the interface went away (backstop sweep is %s)", took, rebindInterval)
}

// A poke has to work whether or not anyone is listening yet, and must
// never block the data path that calls it.
func TestPokeNeverBlocks(t *testing.T) {
	ps := &pathSet{wake: make(chan struct{}, 1)}
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			ps.poke()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("poke blocked; a failing write would stall the send path")
	}
	if n := len(ps.wake); n != 1 {
		t.Errorf("1000 pokes queued %d wakeups, want 1", n)
	}
}

// The settle logic has to tell "not ready yet" apart from "not there".
//
// An interface that exists but cannot be bound is mid-transition and worth
// looking at again in milliseconds. An interface that is simply absent is a
// link in a dead zone, and polling it hard for hours costs power and CPU on
// a box running off a battery, to discover nothing. Only the first is
// pending.
func TestReconcileDistinguishesNotReadyFromNotThere(t *testing.T) {
	requireNetlink(t)
	sess := newSession(nil, "test", roleInitiator)
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}

	t.Run("absent interface is not pending", func(t *testing.T) {
		ps := newPathSet([]pathSpec{{id: 0, name: "definitely-absent0"}}, sess, remote, func(uint8, []byte) {})
		if ps.reconcile() {
			t.Error("an absent link reported pending; that would poll a dead zone at 100ms forever")
		}
	})

	t.Run("present but unaddressed is pending", func(t *testing.T) {
		d, err := tun.Open(tun.Config{Name: "ompnl3", MTU: 1300}) // up, no address
		if err != nil {
			t.Skipf("cannot create device: %v", err)
		}
		defer d.Close()

		ps := newPathSet([]pathSpec{{id: 1, name: "ompnl3"}}, sess, remote, func(uint8, []byte) {})
		if !ps.reconcile() {
			t.Error("an interface that exists but has no address yet reported settled;" +
				" a modem mid-DHCP would wait out the full sweep")
		}
	})

	t.Run("bound interface is not pending", func(t *testing.T) {
		d, err := tun.Open(tun.Config{Name: "ompnl4", MTU: 1300, Address: netip.MustParsePrefix("10.98.4.1/24")})
		if err != nil {
			t.Skipf("cannot create device: %v", err)
		}
		defer d.Close()

		ps := newPathSet([]pathSpec{{id: 2, name: "ompnl4"}}, sess, remote, func(uint8, []byte) {})
		sess.registerPath(2)
		if ps.reconcile() {
			t.Error("a healthy bound path reported pending; the sweep would never go lazy")
		}
	})
}
