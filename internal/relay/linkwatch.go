package relay

import (
	"fmt"
	"sync/atomic"
	"syscall"
)

// Link state is an event, not something to poll for.
//
// D-029 measured what polling costs. When a WAN link's interface went away,
// the scheduler moved the flow in the same second it was told - but it was
// told up to a full reconcile interval late, so a clean link loss cost
// roughly three seconds of traffic against protocol.md's 100-200 ms
// reaction target. Nothing in the state machine could have recovered that,
// because the state machine was not what was late.
//
// The kernel already announces this. RTM_NEWLINK and RTM_DELLINK arrive as
// an interface appears or goes, and RTM_NEWADDR and RTM_DELADDR as its
// addresses move - which is the other half of what a path cares about,
// since a lease renewal under CGNAT changes the address without the link
// ever going down.
//
// This is a notification only. It carries no detail about what changed and
// deliberately does not parse the message body: the reconcile it wakes
// already reads interface state directly and is the single place that
// decides what a path should do. Adding a second, parallel interpretation
// of link state would be two things to keep in agreement.

// Multicast group masks from the kernel's linux/rtnetlink.h. Go's syscall
// package names the message types but not the groups to subscribe to, so
// they are written down here the same way ipPMTUDiscProbe is - they are
// ABI and do not move.
const (
	rtmgrpLink       = 0x1
	rtmgrpIPv4IfAddr = 0x10
)

// linkEvents is the coalescing notification channel. A buffered channel of
// one is the whole coalescing strategy: bringing an interface up emits
// several messages in a burst, and reconciling once after them is both
// correct and what a reader wants. A send that would block means a wakeup
// is already pending, so dropping it loses nothing.
type linkWatcher struct {
	events  chan struct{}
	fd      int
	stopped atomic.Bool
}

// watchLinks subscribes to interface and address changes.
//
// A failure here is not fatal to the daemon and callers are expected to
// carry on with the periodic reconcile: a slower daemon is a working
// daemon, and principle 5 asks for a defined behaviour when the thing
// underneath is broken, not for an exit.
func watchLinks() (*linkWatcher, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Groups: rtmgrpLink | rtmgrpIPv4IfAddr,
	}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("netlink bind: %w", err)
	}

	w := &linkWatcher{events: make(chan struct{}, 1), fd: fd}
	go w.read()
	return w, nil
}

// C is the channel to select on.
func (w *linkWatcher) C() <-chan struct{} { return w.events }

// Stop releases the socket, which ends the read loop.
func (w *linkWatcher) Stop() {
	if w.stopped.CompareAndSwap(false, true) {
		syscall.Close(w.fd)
	}
}

func (w *linkWatcher) read() {
	// Sized for a burst of messages rather than one. The kernel will
	// truncate a multicast message that does not fit and the notification
	// would be lost, and a lost notification here is a path that stays
	// wrong until the next periodic reconcile - exactly the latency this
	// exists to remove.
	buf := make([]byte, 65536)
	for {
		n, _, err := syscall.Recvfrom(w.fd, buf, 0)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return // socket closed, or unreadable; the periodic reconcile carries on
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			continue
		}
		// One wakeup per batch, not per message. Bringing an interface
		// up emits several of these together and they all mean the same
		// thing to the reconcile that follows.
		interesting := false
		for _, m := range msgs {
			switch m.Header.Type {
			case syscall.RTM_NEWLINK, syscall.RTM_DELLINK,
				syscall.RTM_NEWADDR, syscall.RTM_DELADDR:
				interesting = true
			}
		}
		if interesting {
			w.notify()
		}
	}
}

func (w *linkWatcher) notify() {
	select {
	case w.events <- struct{}{}:
	default: // a wakeup is already pending; one reconcile covers both
	}
}
