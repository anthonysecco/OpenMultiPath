package relay

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"syscall"

	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

// PathConfig is one physical WAN link the initiator sends duplicate copies
// of every packet out of.
type PathConfig struct {
	Name string // e.g. "enp1s0", for logging only
	Bind string // local IP to bind to, forcing egress via that link's route
}

type InitiatorConfig struct {
	LoopbackAddr string // where the local WireGuard peer sends to/listens on
	Paths        []PathConfig
	RemoteAddr   string // home's public endpoint, e.g. "162.231.243.253:48219"
}

// RunInitiator relays between a local WireGuard interface and the home
// endpoint, duplicating every packet across every configured path. It
// blocks until a fatal error occurs.
func RunInitiator(cfg InitiatorConfig) error {
	if len(cfg.Paths) == 0 {
		return fmt.Errorf("relay: initiator needs at least one path")
	}

	wgAddr, err := net.ResolveUDPAddr("udp", cfg.LoopbackAddr)
	if err != nil {
		return fmt.Errorf("relay: resolve loopback addr: %w", err)
	}
	wgConn, err := net.ListenUDP("udp", wgAddr)
	if err != nil {
		return fmt.Errorf("relay: listen on loopback: %w", err)
	}
	defer wgConn.Close()

	remoteAddr, err := net.ResolveUDPAddr("udp", cfg.RemoteAddr)
	if err != nil {
		return fmt.Errorf("relay: resolve remote addr: %w", err)
	}

	pathConns := make([]*net.UDPConn, 0, len(cfg.Paths))
	for _, p := range cfg.Paths {
		conn, err := listenOnDevice(p.Name, p.Bind)
		if err != nil {
			return fmt.Errorf("relay: bind path %s (%s): %w", p.Name, p.Bind, err)
		}
		defer conn.Close()
		pathConns = append(pathConns, conn)
		log.Printf("initiator: path %s bound to %s, sending to %s", p.Name, p.Bind, cfg.RemoteAddr)
	}

	// The address the local WireGuard peer sends from, learned from its
	// first outbound packet, and where inbound replies get delivered.
	var wgPeer atomic.Pointer[net.UDPAddr]

	sess := newSession()
	go sess.logStats()

	// WireGuard -> duplicate onto every physical path. The global sequence
	// is allocated once here, before the copies are made, so every copy of
	// a packet is recognisable as the same packet at the far end.
	// readLoop calls this from a single goroutine, so one scratch buffer
	// serves every copy: each is written out before the next is built.
	scratch := make([]byte, 0, bufSize+maxHeaderLen)
	go readLoop(wgConn, "initiator-wg", func(payload []byte, from *net.UDPAddr) {
		wgPeer.Store(from)
		globalSeq := sess.nextGlobalSeq()
		for i, conn := range pathConns {
			out := sess.stamp(uint8(i), globalSeq, payload, scratch)
			if _, err := conn.WriteToUDP(out, remoteAddr); err != nil {
				log.Printf("initiator: write to path %s failed: %v", cfg.Paths[i].Name, err)
			}
		}
	})

	// Each physical path -> local WireGuard. Duplicates land here too;
	// WireGuard's replay protection drops the redundant copy.
	for i, conn := range pathConns {
		name := cfg.Paths[i].Name
		go readLoop(conn, "initiator-path-"+name, func(buf []byte, _ *net.UDPAddr) {
			h, payload, err := protocol.Parse(buf)
			if err != nil {
				log.Printf("initiator: bad packet on path %s: %v", name, err)
				return
			}
			sess.observe(&h)

			peer := wgPeer.Load()
			if peer == nil {
				return // haven't heard from local WireGuard yet
			}
			if _, err := wgConn.WriteToUDP(payload, peer); err != nil {
				log.Printf("initiator: write to wireguard failed: %v", err)
			}
		})
	}

	select {} // run forever; readLoop goroutines log and return on fatal errors
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
				controlErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifaceName)
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
