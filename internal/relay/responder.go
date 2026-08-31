package relay

import (
	"fmt"
	"log"
	"net"

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
	pubAddr, err := net.ResolveUDPAddr("udp", cfg.PublicAddr)
	if err != nil {
		return fmt.Errorf("relay: resolve public addr: %w", err)
	}
	pubConn, err := net.ListenUDP("udp", pubAddr)
	if err != nil {
		return fmt.Errorf("relay: listen on public addr: %w", err)
	}
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
		sess.observe(&h)
		sess.setRemote(h.PathID, from)

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
