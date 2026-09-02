package relay

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/anthonysecco/OpenMultiPath/internal/tun"
)

// The local endpoint is the side of the daemon facing this box's own
// traffic, as opposed to the paths facing the other box. D-020 changes
// what sits there and nothing else, which is why it is worth naming as a
// seam rather than editing in place.
//
// Below WireGuard - the shape the daemon was built with - the local
// endpoint is a loopback UDP socket that WireGuard sends its already
// encrypted packets to. The payloads are ciphertext, so the daemon can
// sequence and schedule them but can never look inside one.
//
// Above WireGuard, which is what D-020 moves to, the local endpoint is a
// TUN device and the payloads are plaintext inner IP packets. That is the
// entire point: classification needs a 5-tuple, the behavioural heuristic
// needs per-flow packet sizes and gaps, and neither exists on the far side
// of a crypto boundary.
//
// Everything between the two - the header, sequencing, measurement,
// scoring, scheduling - is identical either way and does not know which is
// in use. Both are kept because principle 5 says a bad update from 800
// miles away has to be one flag back rather than an unreachable vehicle.
type localEndpoint interface {
	// readPayloads delivers each payload to handle until the endpoint
	// fails, then returns.
	readPayloads(name string, handle func(payload []byte))

	// write sends one payload toward this box's own stack.
	write(payload []byte) error

	// describe names the endpoint for the log line at startup.
	describe() string

	// plaintext reports whether payloads are inner IP packets that can be
	// looked inside, rather than ciphertext. It is what gates
	// classification: below WireGuard the payload is an encrypted blob,
	// and running a 5-tuple parser over one would not fail loudly - it
	// would find plausible-looking garbage and classify traffic on it.
	plaintext() bool

	Close() error
}

// loopbackEndpoint relays to a local WireGuard interface over loopback,
// which is the daemon's original shape and remains the default.
type loopbackEndpoint struct {
	conn *net.UDPConn

	// target is where payloads are written. The responder knows it up
	// front - WireGuard's own listen address - while the initiator has
	// to learn it from WireGuard's first outbound packet, because the
	// source port is ephemeral and chosen by WireGuard.
	target *net.UDPAddr
	peer   atomic.Pointer[net.UDPAddr]
}

func (e *loopbackEndpoint) readPayloads(name string, handle func(payload []byte)) {
	readLoop(e.conn, name, func(buf []byte, from *net.UDPAddr) {
		if e.target == nil {
			e.peer.Store(from)
		}
		handle(buf)
	})
}

func (e *loopbackEndpoint) write(payload []byte) error {
	dst := e.target
	if dst == nil {
		dst = e.peer.Load()
		if dst == nil {
			// WireGuard has not spoken yet, so there is nowhere to
			// deliver to. Dropping is correct: the tunnel is not up.
			return nil
		}
	}
	_, err := e.conn.WriteToUDP(payload, dst)
	return err
}

func (e *loopbackEndpoint) describe() string {
	if e.target != nil {
		return fmt.Sprintf("loopback to wireguard at %s (below WireGuard)", e.target)
	}
	return fmt.Sprintf("loopback on %s, learning wireguard's address (below WireGuard)", e.conn.LocalAddr())
}

func (e *loopbackEndpoint) plaintext() bool { return false }

func (e *loopbackEndpoint) Close() error { return e.conn.Close() }

// tunEndpoint reads plaintext inner packets from a TUN device, which is
// what D-020 moves the daemon to.
type tunEndpoint struct {
	dev *tun.Device
	mtu int
}

// readPayloads hands back one inner IP packet at a time.
//
// Not every packet is traffic somebody routed here. The kernel emits its
// own housekeeping on any device - an IGMP membership report arrives on a
// freshly created one - so what comes out of here is not guaranteed to be
// a flow anybody asked for. Classification already treats anything it
// cannot place as ClassUnknown rather than guessing, so this needs no
// filter of its own.
func (e *tunEndpoint) readPayloads(name string, handle func(payload []byte)) {
	buf := make([]byte, bufSize)
	for {
		n, err := e.dev.Read(buf)
		if err != nil {
			// A closed device is how the endpoint is deliberately
			// retired, and the caller already knows. os.File reports
			// that as fs.ErrClosed rather than net.ErrClosed.
			if !errors.Is(err, net.ErrClosed) && !errors.Is(err, fs.ErrClosed) {
				log.Printf("%s: read error: %v", name, err)
			}
			return
		}
		if n == 0 {
			continue
		}
		handle(buf[:n])
	}
}

func (e *tunEndpoint) write(payload []byte) error {
	_, err := e.dev.Write(payload)
	return err
}

func (e *tunEndpoint) describe() string {
	return fmt.Sprintf("tun device %s, mtu %d (above WireGuard, D-020)", e.dev.Name(), e.mtu)
}

func (e *tunEndpoint) plaintext() bool { return true }

func (e *tunEndpoint) Close() error { return e.dev.Close() }

// TunConfig describes the TUN device to run above WireGuard. A zero Name
// keeps the daemon on the loopback relay, which is the default and the
// rollback.
type TunConfig struct {
	Name string
	Addr string // CIDR, e.g. "10.30.0.2/24"
	MTU  int
}

// Enabled reports whether D-020's data path was asked for.
func (c TunConfig) Enabled() bool { return c.Name != "" }

// openTun builds the endpoint for D-020's data path.
func openTun(c TunConfig) (*tunEndpoint, error) {
	cfg := tun.Config{Name: c.Name, MTU: c.MTU}
	if c.Addr != "" {
		p, err := netip.ParsePrefix(c.Addr)
		if err != nil {
			return nil, fmt.Errorf("relay: -tun-addr %q: %w", c.Addr, err)
		}
		cfg.Address = p
	}
	dev, err := tun.Open(cfg)
	if err != nil {
		return nil, err
	}
	mtu, err := dev.MTU()
	if err != nil {
		dev.Close()
		return nil, err
	}
	return &tunEndpoint{dev: dev, mtu: mtu}, nil
}

// newInitiatorEndpoint builds the RV's local endpoint: a TUN device when
// D-020's data path was asked for, otherwise the loopback relay.
func newInitiatorEndpoint(cfg InitiatorConfig) (localEndpoint, error) {
	if cfg.Tun.Enabled() {
		return openTun(cfg.Tun)
	}
	wgAddr, err := net.ResolveUDPAddr("udp", cfg.LoopbackAddr)
	if err != nil {
		return nil, fmt.Errorf("relay: resolve loopback addr: %w", err)
	}
	conn, err := net.ListenUDP("udp", wgAddr)
	if err != nil {
		return nil, fmt.Errorf("relay: listen on loopback: %w", err)
	}
	// No target: the initiator learns WireGuard's ephemeral source port
	// from its first outbound packet.
	return &loopbackEndpoint{conn: conn}, nil
}

// newResponderEndpoint builds home's local endpoint.
func newResponderEndpoint(cfg ResponderConfig) (localEndpoint, error) {
	if cfg.Tun.Enabled() {
		return openTun(cfg.Tun)
	}
	target, err := net.ResolveUDPAddr("udp", cfg.LoopbackTarget)
	if err != nil {
		return nil, fmt.Errorf("relay: resolve wireguard target: %w", err)
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, fmt.Errorf("relay: open loopback socket to wireguard: %w", err)
	}
	return &loopbackEndpoint{conn: conn, target: target}, nil
}
