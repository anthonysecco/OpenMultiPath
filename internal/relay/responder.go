package relay

import (
	"fmt"
	"log"
	"net"
)

type ResponderConfig struct {
	PublicAddr     string // the forwarded port, e.g. "0.0.0.0:48219"
	LoopbackTarget string // local WireGuard's own listen address
}

// RunResponder relays between the public endpoint (reachable from any of
// the RV's physical paths) and a local WireGuard interface, duplicating
// replies to every RV address seen recently. It blocks until a fatal error
// occurs.
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

	knownRVAddrs := newAddrSet()

	// Any RV path -> local WireGuard, remembering where it came from.
	go readLoop(pubConn, "responder-public", func(buf []byte, from *net.UDPAddr) {
		knownRVAddrs.add(from)
		if _, err := wgConn.WriteToUDP(buf, wgTarget); err != nil {
			log.Printf("responder: write to wireguard failed: %v", err)
		}
	})

	// WireGuard -> duplicate the reply to every RV path address seen so far.
	go readLoop(wgConn, "responder-wg", func(buf []byte, _ *net.UDPAddr) {
		for _, addr := range knownRVAddrs.snapshot() {
			if _, err := pubConn.WriteToUDP(buf, addr); err != nil {
				log.Printf("responder: write to %s failed: %v", addr, err)
			}
		}
	})

	select {}
}
