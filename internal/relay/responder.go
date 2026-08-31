package relay

import (
	"context"
	"fmt"
	"log"
	"net"
	"syscall"

	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

type ResponderConfig struct {
	PublicAddr     string // the forwarded port, e.g. "0.0.0.0:48219"
	LoopbackTarget string // local WireGuard's own listen address
}

// RunResponder relays between the public endpoint, reachable from any of
// the RV's physical paths, and a local WireGuard interface. Replies are
// duplicated back over every path currently being heard from. It blocks
// until a fatal error occurs.
func RunResponder(cfg ResponderConfig) error {
	// The public socket also carries this end's MTU probes back toward the
	// RV, so it needs the same don't-fragment marking: paths are
	// asymmetric and each direction has to be measured on its own.
	var controlErr error
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) { controlErr = setDontFragment(int(fd)) })
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp", cfg.PublicAddr)
	if err != nil {
		return fmt.Errorf("relay: listen on public addr: %w", err)
	}
	if controlErr != nil {
		pc.Close()
		return fmt.Errorf("relay: set don't-fragment on public socket: %w", controlErr)
	}
	pubConn := pc.(*net.UDPConn)
	defer pubConn.Close()

	wgTarget, err := net.ResolveUDPAddr("udp", cfg.LoopbackTarget)
	if err != nil {
		return fmt.Errorf("relay: resolve wireguard target: %w", err)
	}
	wgConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return fmt.Errorf("relay: open loopback socket to wireguard: %w", err)
	}
	defer wgConn.Close()

	sess := newSession()
	go sess.logStats()

	// The responder never dials out, so its paths are only the ones the
	// far end has made contact on.
	go sess.runProbes(
		func() []uint8 {
			rs := sess.remotes()
			ids := make([]uint8, len(rs))
			for i, r := range rs {
				ids[i] = r.pathID
			}
			return ids
		},
		func(id uint8, pkt []byte) {
			addr := sess.remoteFor(id)
			if addr == nil {
				return
			}
			if _, err := pubConn.WriteToUDP(pkt, addr); err != nil {
				log.Printf("responder: probe on path %d failed: %v", id, err)
			}
		},
	)

	// Any RV path -> local WireGuard. Which path a packet came in on is
	// taken from the header rather than inferred from its source address,
	// which is what makes the return route survive the RV's addresses
	// moving under CGNAT: the address is merely recorded against the path
	// the header names.
	go readLoop(pubConn, "responder-public", func(buf []byte, from *net.UDPAddr) {
		h, payload, err := protocol.Parse(buf)
		if err != nil {
			log.Printf("responder: bad packet from %s: %v", from, err)
			return
		}
		sess.observe(&h, len(buf))
		sess.setRemote(h.PathID, from)

		// Reports and probes carry no tunnel traffic; they exist only to
		// keep measurement flowing when data is not.
		if h.Type != protocol.TypeData {
			return
		}
		if _, err := wgConn.WriteToUDP(payload, wgTarget); err != nil {
			log.Printf("responder: write to wireguard failed: %v", err)
		}
	})

	// WireGuard -> duplicate the reply back over every known path.
	scratch := make([]byte, 0, bufSize+maxHeaderLen)
	go readLoop(wgConn, "responder-wg", func(payload []byte, _ *net.UDPAddr) {
		globalSeq := sess.nextGlobalSeq()
		for _, r := range sess.remotes() {
			out := sess.stamp(r.pathID, globalSeq, payload, scratch)
			if _, err := pubConn.WriteToUDP(out, r.addr); err != nil {
				log.Printf("responder: write to path %d at %s failed: %v", r.pathID, r.addr, err)
			}
		}
	})

	select {}
}
