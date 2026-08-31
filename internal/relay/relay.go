// Package relay is a placeholder transport layer for the OpenMultiPath daemon.
//
// It sits between the local WireGuard interface (which talks only to
// loopback) and the physical WAN links, blindly duplicating every packet
// across all paths in both directions. There is no header, sequencing, or
// path selection yet - WireGuard's own replay protection is what silently
// drops the duplicate copies. This exists so the WireGuard interfaces could
// be collapsed to a single loopback-facing tunnel per scope-v1.md's
// intended design without leaving the tunnel non-functional in the
// meantime; the header and real path selection land on top of this.
package relay

import (
	"log"
	"net"
	"sync"
)

const bufSize = 2048

// addrSet tracks the distinct peer addresses recently seen, so the
// responder knows where to duplicate its replies to.
type addrSet struct {
	mu   sync.RWMutex
	seen map[string]*net.UDPAddr
}

func newAddrSet() *addrSet {
	return &addrSet{seen: make(map[string]*net.UDPAddr)}
}

func (s *addrSet) add(addr *net.UDPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen[addr.String()] = addr
}

func (s *addrSet) snapshot() []*net.UDPAddr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*net.UDPAddr, 0, len(s.seen))
	for _, a := range s.seen {
		out = append(out, a)
	}
	return out
}

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
