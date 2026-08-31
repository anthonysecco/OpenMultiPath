// Package relay is the transport layer of the OpenMultiPath daemon.
//
// It sits between the local WireGuard interface, which talks only to
// loopback, and the physical WAN links. Every packet is wrapped in the
// header from internal/protocol, carrying the sequence numbers and
// timestamps that per-path measurement is built on, then duplicated across
// all paths in both directions.
//
// Duplication is currently unconditional, and WireGuard's own replay
// protection is what drops the redundant copies. That is deliberate for
// now: scope-v1.md wants the tunnel carrying traffic with full per-path
// telemetry before any scheduling logic exists, so there is no scoring,
// no path selection, and no classification here yet. Once those land,
// duplication becomes a policy decision per class and budget band rather
// than the only behaviour.
package relay

import (
	"log"
	"net"
)

const bufSize = 2048

// maxHeaderLen is the headroom reserved for the wire header when building
// an outgoing packet. The echo block grows with the number of paths, so
// this is sized well past any realistic path count rather than exactly;
// append handles anything larger correctly, just with an allocation.
const maxHeaderLen = 256

func readLoop(conn *net.UDPConn, name string, handle func(buf []byte, from *net.UDPAddr)) {
	buf := make([]byte, bufSize)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("%s: read error: %v", name, err)
			return
		}
		handle(buf[:n], from)
	}
}
