package relay

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// A WAN link is not a fact established at startup. Modems take thirty
// seconds or more to register, Starlink takes a minute or two to acquire,
// and both hand back a different address after a tower handover or a lease
// renewal. scope-v1.md is blunt about this being the single most likely
// thing to bite: enumerating once at boot and assuming that is the world
// fails on every power-on.
//
// So paths are reconciled continuously rather than bound once. A link that
// is missing is not an error, it is a path that is currently down; a link
// whose address moved is rebound onto the new one. The daemon starts and
// keeps running with none of its links present, because the alternative -
// exiting - is the one state from which nothing can recover.

// rebindInterval is how often the configured links are re-examined for
// appearance, disappearance and address changes. Fast enough that a modem
// finishing registration is picked up promptly, slow enough to be free.
const rebindInterval = 2 * time.Second

// pathSpec is one configured WAN link. The address is deliberately not
// part of it unless pinned: the address is the thing that changes.
type pathSpec struct {
	id   uint8
	name string // interface name, e.g. "enp1s0"
	pin  string // explicit local IP; empty means discover it from the interface
}

// boundPath is a path's currently open socket.
type boundPath struct {
	conn  *net.UDPConn
	local string // the local IP this socket is bound to

	// failing suppresses repeated write-failure logging. A link whose
	// route has gone while its address remains - a modem attached with no
	// PDP context, which is an ordinary dead-zone state - fails every
	// write at the report cadence, and logging each one fills the journal
	// on the box that is hardest to reach. The transition is what is
	// worth recording, not the ten per second that follow it.
	failing atomic.Bool
}

// pathSet owns the initiator's physical sockets and keeps them matching
// the links that actually exist.
type pathSet struct {
	specs   []pathSpec
	sess    *session
	onData  func(id uint8, buf []byte)
	dialing *net.UDPAddr // where every path sends

	mu    sync.RWMutex
	bound map[uint8]*boundPath
}

func newPathSet(specs []pathSpec, sess *session, remote *net.UDPAddr, onData func(id uint8, buf []byte)) *pathSet {
	return &pathSet{
		specs:   specs,
		sess:    sess,
		onData:  onData,
		dialing: remote,
		bound:   make(map[uint8]*boundPath),
	}
}

// run reconciles the sockets against reality forever. It returns only if
// the reconcile loop itself is stopped, which it never is.
func (ps *pathSet) run() {
	ps.reconcile() // once immediately, so a link already present is not waited on
	for range time.Tick(rebindInterval) {
		ps.reconcile()
	}
}

// reconcile brings every configured path into line with the address its
// interface currently has, binding what appeared, dropping what vanished
// and rebinding what moved.
func (ps *pathSet) reconcile() {
	for _, spec := range ps.specs {
		want, err := spec.localIP()

		ps.mu.RLock()
		have := ps.bound[spec.id]
		ps.mu.RUnlock()

		switch {
		case err != nil:
			// No usable address. The link is down, or has not come up
			// yet, or has lost its lease. All three are the same thing
			// from here and none of them is fatal.
			if have != nil {
				ps.drop(spec, fmt.Sprintf("%v", err))
			}
		case have == nil:
			ps.bind(spec, want)
		case have.local != want:
			// The lease moved under us. The old socket is bound to an
			// address that no longer exists and will never deliver
			// another packet, so it has to be replaced rather than kept.
			log.Printf("path %d (%s): address changed %s -> %s, rebinding", spec.id, spec.name, have.local, want)
			ps.drop(spec, "address changed")
			ps.bind(spec, want)
		}
	}
}

// localIP reports the address this path should currently bind to, or an
// error describing why it cannot be bound at all.
func (s pathSpec) localIP() (string, error) {
	if s.pin != "" {
		// A pinned address still has to actually be present; pinning
		// says which address to use, not that the link is up.
		if !addrPresent(s.name, s.pin) {
			return "", fmt.Errorf("pinned address %s not present on %s", s.pin, s.name)
		}
		return s.pin, nil
	}

	iface, err := net.InterfaceByName(s.name)
	if err != nil {
		return "", fmt.Errorf("interface %s not present", s.name)
	}
	if iface.Flags&net.FlagUp == 0 {
		return "", fmt.Errorf("interface %s is down", s.name)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("interface %s addresses unreadable: %w", s.name, err)
	}
	ip, ok := pickIPv4(addrs)
	if !ok {
		return "", fmt.Errorf("interface %s has no usable IPv4 address", s.name)
	}
	return ip, nil
}

// pickIPv4 chooses which of an interface's addresses to bind to.
//
// IPv4 only for now: the sockets carry IPv4 don't-fragment marking and the
// home endpoint is v4. A link holding only a v6 address reads as having no
// usable address, which is the truth as far as this daemon is concerned.
//
// Link-local is skipped rather than accepted. A cellular interface carries
// a 169.254 address in the window between the link coming up and DHCP
// completing, and binding to it would produce a path that looks up and
// delivers nothing - the worst of the available outcomes, since the next
// reconcile would see a bound socket and leave it alone.
func pickIPv4(addrs []net.Addr) (string, bool) {
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := n.IP.To4()
		if ip == nil || !ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() {
			continue
		}
		return ip.String(), true
	}
	return "", false
}

// addrPresent reports whether a pinned address is still configured on its
// interface.
func addrPresent(name, ip string) bool {
	iface, err := net.InterfaceByName(name)
	if err != nil || iface.Flags&net.FlagUp == 0 {
		return false
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.String() == ip {
			return true
		}
	}
	return false
}

// bind opens a path's socket and starts reading from it. A failure is
// logged and left for the next reconcile rather than propagated: a link
// that cannot be bound this second is simply still down.
func (ps *pathSet) bind(spec pathSpec, local string) {
	conn, err := listenOnDevice(spec.name, local)
	if err != nil {
		log.Printf("path %d (%s): bind to %s failed: %v", spec.id, spec.name, local, err)
		return
	}

	ps.mu.Lock()
	ps.bound[spec.id] = &boundPath{conn: conn, local: local}
	ps.mu.Unlock()

	ps.sess.setBound(spec.id, local)
	log.Printf("path %d (%s): up, bound to %s, sending to %s", spec.id, spec.name, local, ps.dialing)

	go readLoop(conn, fmt.Sprintf("initiator-path-%s", spec.name), func(buf []byte, _ *net.UDPAddr) {
		ps.onData(spec.id, buf)
	})
}

// drop closes a path's socket, which also ends its read loop.
func (ps *pathSet) drop(spec pathSpec, why string) {
	ps.mu.Lock()
	bp := ps.bound[spec.id]
	delete(ps.bound, spec.id)
	ps.mu.Unlock()

	if bp == nil {
		return
	}
	bp.conn.Close()
	ps.sess.setUnbound(spec.id)
	log.Printf("path %d (%s): down (%s)", spec.id, spec.name, why)
}

// send writes one packet out a path, if that path is currently bound.
// Sending on a down path is not an error worth reporting - it is the
// expected state of a link in a dead zone - so it is silently dropped.
func (ps *pathSet) send(id uint8, pkt []byte) {
	ps.mu.RLock()
	bp := ps.bound[id]
	ps.mu.RUnlock()

	if bp == nil {
		return
	}
	_, err := bp.conn.WriteToUDP(pkt, ps.dialing)
	switch {
	case err == nil:
		if bp.failing.CompareAndSwap(true, false) {
			log.Printf("path %d: writing again", id)
		}
	case errors.Is(err, net.ErrClosed):
		// The path was retired underneath this write, which the caller
		// has already logged.
	default:
		// A write failing on a bound socket means the route went away
		// while the address stayed. The next reconcile drops the path if
		// the address goes too; if it does not, the path stays bound and
		// silent, which the measurement layer reports as a path
		// delivering nothing. Nothing here can do better than say so once.
		if bp.failing.CompareAndSwap(false, true) {
			log.Printf("path %d: write failed, suppressing until it recovers: %v", id, err)
		}
	}
}

// active lists the paths currently bound, which are the only ones worth
// sending probes and reports down.
func (ps *pathSet) active() []uint8 {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	out := make([]uint8, 0, len(ps.bound))
	for id := range ps.bound {
		out = append(out, id)
	}
	return out
}

// listenOnDevice opens a UDP socket bound to both a specific local IP and a
// specific network interface (SO_BINDTODEVICE), so egress is pinned to that
// physical link regardless of what the main routing table would otherwise
// pick. Binding the local IP alone is not enough - Linux's weak host model
// will happily route out a different interface for a destination-based
// lookup even when the source address belongs to another NIC.
func listenOnDevice(ifaceName, bindIP string) (*net.UDPConn, error) {
	var controlErr error
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if controlErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifaceName); controlErr != nil {
					return
				}
				controlErr = setDontFragment(int(fd))
			})
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp", bindIP+":0")
	if err != nil {
		return nil, err
	}
	if controlErr != nil {
		pc.Close()
		return nil, fmt.Errorf("SO_BINDTODEVICE %s: %w", ifaceName, controlErr)
	}
	return pc.(*net.UDPConn), nil
}
