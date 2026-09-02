package relay

import (
	"context"
	"fmt"
	"log"
	"net"
	"syscall"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
	"github.com/anthonysecco/OpenMultiPath/internal/record"
)

type ResponderConfig struct {
	PublicAddr     string // the forwarded port, e.g. "0.0.0.0:48219"
	LoopbackTarget string // local WireGuard's own listen address

	Node        string         // this box's name, for the web interface
	StatePath   string         // where to write the snapshot the interface reads
	RecordPath  string         // where to append the history log; empty disables it
	WGInterface string         // tunnel interface, read for its current MTU
	Settings    *config.Holder // adjustable settings, reloaded while running

	// AuthKey authenticates the wire header. Empty runs unauthenticated,
	// which is the current default; see relay.LoadAuthKey.
	AuthKey []byte
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

	sess := newSession(cfg.Settings, cfg.Node, roleResponder)
	sess.setAuthKey(cfg.AuthKey)
	go sess.logStats()
	if cfg.StatePath != "" {
		go sess.writeState(cfg.StatePath, cfg.WGInterface)
	}
	// The home end records too. It sees the same links from the other
	// side, and asymmetry is one of the things the field data has to
	// settle - a path can be fine outbound and unusable inbound.
	if cfg.RecordPath != "" {
		w := record.New(cfg.RecordPath, func() (int64, int) {
			c := cfg.Settings.Get()
			return c.RecordMaxBytes(), c.RecordKeepFiles
		})
		log.Printf("responder: recording history to %s", cfg.RecordPath)
		go sess.recordHistory(w, cfg.WGInterface)
	}

	// The responder never dials out, so its paths are only the ones the
	// far end has made contact on.
	known := func() []uint8 {
		rs := sess.remotes()
		ids := make([]uint8, len(rs))
		for i, r := range rs {
			ids[i] = r.pathID
		}
		return ids
	}

	go sess.runProbes(
		known,
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
		h, payload, ver, err := protocol.Parse(buf, sess.authKey)
		if err != nil {
			log.Printf("responder: bad packet from %s: %v", from, err)
			return
		}
		sess.notePeerVersion(ver)
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

	sched := newScheduler(sess, cfg.Settings, known)
	sess.sched = sched
	go sched.run()

	// WireGuard -> whichever paths the scheduler has chosen.
	//
	// Both ends schedule independently and neither tells the other what it
	// decided. That is deliberate: paths are asymmetric, a link can be
	// clean inbound and unusable outbound, and each end has measured its
	// own receive direction directly rather than been told about it.
	scratch := make([]byte, 0, bufSize+maxHeaderLen)
	go readLoop(wgConn, "responder-wg", func(payload []byte, _ *net.UDPAddr) {
		globalSeq := sess.nextGlobalSeq()

		tx := sched.txPaths()
		if len(tx) == 0 {
			tx = known()
		}
		for _, id := range tx {
			addr := sess.remoteFor(id)
			if addr == nil {
				continue // never heard from, so nowhere to send
			}
			out := sess.stamp(id, globalSeq, payload, scratch)
			if _, err := pubConn.WriteToUDP(out, addr); err != nil {
				log.Printf("responder: write to path %d at %s failed: %v", id, addr, err)
			}
		}
	})

	select {}
}
