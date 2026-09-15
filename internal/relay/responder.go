package relay

import (
	"context"
	"fmt"
	"log"
	"net"
	"syscall"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
	"github.com/anthonysecco/OpenMultiPath/internal/lan"
	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
	"github.com/anthonysecco/OpenMultiPath/internal/record"
	"github.com/anthonysecco/OpenMultiPath/internal/wan"
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

	// Tun runs D-020's data path - above WireGuard, writing plaintext
	// inner packets into the host stack for egress - when its Name is
	// set. Empty keeps the loopback relay.
	Tun TunConfig

	// LANRoutesPath is where the vehicle's LAN subnets are kept once it has
	// sent them, so they are routed again at startup (D-068). Only used on a
	// TUN, where home owns the routes into the tunnel.
	LANRoutesPath string

	// WGTransport is home's WireGuard interface for the vehicle's transports,
	// and WGTransportConf its wg-quick file. Home adds a peer to both for any
	// transport the vehicle reports that it lacks (D-070). Only on a TUN.
	WGTransport     string
	WGTransportConf string
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

	local, err := newResponderEndpoint(cfg)
	if err != nil {
		return err
	}
	defer local.Close()
	log.Printf("responder: local endpoint is %s", local.describe())

	sess := newSession(cfg.Settings, cfg.Node, roleResponder)
	sess.setAuthKey(cfg.AuthKey)

	// Routes back to the vehicle's LANs (D-068). Only on a TUN: below
	// WireGuard the routes point at wg0, which wg-quick owns. The device
	// exists by now, so the set kept from last time goes straight back in
	// rather than waiting for the vehicle to be reachable.
	if cfg.Tun.Enabled() {
		hr := &lan.HomeRoutes{Tun: cfg.Tun.Name, Path: cfg.LANRoutesPath}
		sess.setLANApplier(hr.Apply, hr.Restore())
		if cfg.WGTransport != "" {
			hp := &wan.HomePeers{Interface: cfg.WGTransport, ConfPath: cfg.WGTransportConf}
			sess.setTransportsApplier(hp.Apply)
		}
	}

	// v0.2: bulk the far end spread across paths is put back in order here
	// before it reaches the local endpoint. Only packets carrying a flow
	// sequence go through it; everything else is written straight through.
	sess.reseq = newResequencer(local.write, sess.elapsed)
	go sess.reseq.run()
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

	// Every packet leaves by the public socket, addressed to wherever the
	// path was last heard from. Above WireGuard that socket is on home's
	// WireGuard interface, so each packet picks up WireGuard's framing on its
	// way to the link and the shapers count it (D-055).
	sess.setPathWriter(func(id uint8, pkt []byte) {
		addr := sess.remoteFor(id)
		if addr == nil {
			return // never heard from, so nowhere to send
		}
		if _, err := pubConn.WriteToUDP(pkt, addr); err != nil {
			log.Printf("responder: write to path %d at %s failed: %v", id, addr, err)
		}
	}, cfg.Tun.Enabled())

	go sess.runProbes(known, sess.sendControl)

	// Any RV path -> the local endpoint. Which path a packet came in on is
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

		// The vehicle's measured link speeds (D-055). Answered on the path
		// they arrived on, which is the one known to be working.
		if h.Type == protocol.TypeLinkSpeed {
			if ack := sess.receiveLinkSpeeds(payload); ack != nil {
				sess.sendControl(h.PathID, sess.build(protocol.TypeLinkSpeedAck, h.PathID, sess.nextGlobalSeq(), ack, make([]byte, 0, maxHeaderLen+len(ack))))
			}
			return
		}

		// The vehicle's LAN subnets (D-068), answered the same way.
		if h.Type == protocol.TypeLANRoutes {
			if ack := sess.receiveLANRoutes(payload); ack != nil {
				sess.sendControl(h.PathID, sess.build(protocol.TypeLANRoutesAck, h.PathID, sess.nextGlobalSeq(), ack, make([]byte, 0, maxHeaderLen+len(ack))))
			}
			return
		}

		// The vehicle's transports (D-070), answered the same way.
		if h.Type == protocol.TypeTransports {
			if ack := sess.receiveTransports(payload); ack != nil {
				sess.sendControl(h.PathID, sess.build(protocol.TypeTransportsAck, h.PathID, sess.nextGlobalSeq(), ack, make([]byte, 0, maxHeaderLen+len(ack))))
			}
			return
		}

		// Reports and probes carry no tunnel traffic; they exist only to
		// keep measurement flowing when data is not.
		if h.Type != protocol.TypeData {
			return
		}

		// One delivery per packet, however many copies arrive. See
		// dedup.go: WireGuard's replay window used to do this
		// underneath, and D-020 moved the daemon above it.
		if err := sess.deliverData(&h, payload, local.write); err != nil {
			log.Printf("responder: write to local endpoint failed: %v", err)
		}
	})

	sched := newScheduler(sess, cfg.Settings, known)
	sess.sched = sched
	go sched.run()

	// Local endpoint -> whichever paths the scheduler has chosen.
	//
	// Both ends schedule independently and neither tells the other what it
	// decided. That is deliberate: paths are asymmetric, a link can be
	// clean inbound and unusable outbound, and each end has measured its
	// own receive direction directly rather than been told about it.
	// Step 7. Only runs when the endpoint hands back plaintext; see
	// flowClassifier.
	clf := newFlowClassifier(local, cfg.Settings)
	sess.classifier = clf
	sched.setClassifying(clf.enabled())
	if clf.enabled() {
		log.Printf("%s: classifying traffic (STUN, vendor prefixes, behaviour)", "responder")
	} else {
		log.Printf("%s: not classifying - payloads are ciphertext below WireGuard", "responder")
	}

	go local.readPayloads("responder-local", func(payload []byte) {
		class := clf.classify(payload)
		sess.noteClass(class)

		// Step 9. Classification happens first and unconditionally: the
		// classifier learns a flow from the packets it sees, so gating it
		// on admission would stop a call being recognised precisely when
		// it starts during congestion.
		if !sched.admit(class) {
			sess.noteWithheld()
			return
		}

		// Placement before sequencing; see the initiator.
		flow := flowHash(payload)
		tx, send := sched.txForPacket(class, flow, len(payload))
		if !send {
			return
		}
		if len(tx) == 0 {
			tx = known()
		}
		globalSeq := sess.nextGlobalSeq()
		var tag flowTag
		if class == protocol.ClassBulk {
			tag = sess.nextFlowTag(flow)
		}
		for _, id := range tx {
			if sess.remoteFor(id) == nil {
				continue // never heard from, so nowhere to send
			}
			sess.transmit(id, globalSeq, class, tag, payload)
		}
	})

	select {}
}
