package relay

import (
	"fmt"
	"log"
	"net"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
	"github.com/anthonysecco/OpenMultiPath/internal/record"
)

// PathConfig is one physical WAN link the initiator sends duplicate copies
// of every packet out of.
type PathConfig struct {
	Name string // interface name, e.g. "enp1s0"

	// Bind pins the local IP to bind to. Leave it empty for the normal
	// case: the address is discovered from the interface and rediscovered
	// whenever it changes, which is what lets a path survive a lease
	// renewal or a tower handover. Pinning is for a box with several
	// addresses on one interface where the choice matters.
	Bind string
}

type InitiatorConfig struct {
	LoopbackAddr string // where the local WireGuard peer sends to/listens on
	Paths        []PathConfig
	RemoteAddr   string // home's public endpoint, e.g. "162.231.243.253:48219"

	Node        string         // this box's name, for the web interface
	StatePath   string         // where to write the snapshot the interface reads
	RecordPath  string         // where to append the history log; empty disables it
	WGInterface string         // tunnel interface, read for its current MTU
	Settings    *config.Holder // adjustable settings, reloaded while running

	// AuthKey authenticates the wire header. Empty runs unauthenticated,
	// which is the current default; see relay.LoadAuthKey.
	AuthKey []byte

	// Tun runs D-020's data path - above WireGuard, reading plaintext
	// inner packets - when its Name is set. Empty keeps the loopback
	// relay, which is the default and the way back.
	Tun TunConfig
}

// RunInitiator relays between a local WireGuard interface and the home
// endpoint, duplicating every packet across every path that is currently
// up. It blocks until a fatal error occurs.
//
// A configured link that is absent, down, or has no address yet is not an
// error: it is a path that is currently down, and it will be bound the
// moment it appears. The daemon comes up with none of its links present,
// because on a cold boot in a campground that is the normal case.
func RunInitiator(cfg InitiatorConfig) error {
	if len(cfg.Paths) == 0 {
		return fmt.Errorf("relay: initiator needs at least one path")
	}

	local, err := newInitiatorEndpoint(cfg)
	if err != nil {
		return err
	}
	defer local.Close()
	log.Printf("initiator: local endpoint is %s", local.describe())

	remoteAddr, err := net.ResolveUDPAddr("udp", cfg.RemoteAddr)
	if err != nil {
		return fmt.Errorf("relay: resolve remote addr: %w", err)
	}

	sess := newSession(cfg.Settings, cfg.Node, roleInitiator)
	sess.setAuthKey(cfg.AuthKey)

	// Path ids are indices into the configured list, so a path keeps its
	// identity across every unbind and rebind. A link that vanishes for
	// ten minutes comes back as the same path with its history intact,
	// rather than as a new one starting from nothing.
	specs := make([]pathSpec, len(cfg.Paths))
	for i, p := range cfg.Paths {
		specs[i] = pathSpec{id: uint8(i), name: p.Name, pin: p.Bind}

		// Declare every path up front, bound or not, so a link that has
		// never come up is visible as a path that is down rather than
		// missing from the interface entirely.
		sess.registerPath(uint8(i))
		sess.nameFor(uint8(i), p.Name)
	}

	go sess.logStats()
	if cfg.StatePath != "" {
		go sess.writeState(cfg.StatePath, cfg.WGInterface)
	}
	if cfg.RecordPath != "" {
		w := record.New(cfg.RecordPath, func() (int64, int) {
			c := cfg.Settings.Get()
			return c.RecordMaxBytes(), c.RecordKeepFiles
		})
		log.Printf("initiator: recording history to %s", cfg.RecordPath)
		go sess.recordHistory(w, cfg.WGInterface)
	}

	// Each physical path -> local WireGuard. Duplicates land here too;
	// WireGuard's replay protection drops the redundant copy.
	paths := newPathSet(specs, sess, remoteAddr, func(id uint8, buf []byte) {
		h, payload, ver, err := protocol.Parse(buf, sess.authKey)
		if err != nil {
			log.Printf("initiator: bad packet on path %d: %v", id, err)
			return
		}
		sess.notePeerVersion(ver)
		sess.observe(&h, len(buf))

		// Reports and probes carry no tunnel traffic; they exist only to
		// keep measurement flowing when data is not.
		if h.Type != protocol.TypeData {
			return
		}
		if err := local.write(payload); err != nil {
			log.Printf("initiator: write to local endpoint failed: %v", err)
		}
	})
	go paths.run()

	// Probes and reports go out every bound path, not just the chosen
	// one. That is the whole point of them: passive measurement is
	// structurally blind on an idle path, and an idle path is exactly the
	// one that has to be understood before a call is ever steered onto it.
	go sess.runProbes(paths.active, paths.send)

	sched := newScheduler(sess, cfg.Settings, paths.active)
	sess.sched = sched
	go sched.run()

	// Local endpoint -> whichever paths the scheduler has chosen. The global
	// sequence is allocated once here, before any copies are made, so
	// every copy of a packet is recognisable as the same packet at the far
	// end. readLoop calls this from a single goroutine, so one scratch
	// buffer serves every copy: each is written out before the next is
	// built.
	scratch := make([]byte, 0, bufSize+maxHeaderLen)
	go local.readPayloads("initiator-local", func(payload []byte) {
		globalSeq := sess.nextGlobalSeq()

		// Before the first evaluation the scheduler has no opinion, so
		// fall back to every bound path. Coming up sending nothing would
		// leave the tunnel dead until the first tick.
		tx := sched.txPaths()
		if len(tx) == 0 {
			tx = paths.active()
		}
		for _, id := range tx {
			paths.send(id, sess.stamp(id, globalSeq, payload, scratch))
		}
	})

	select {} // run forever; readLoop goroutines log and return on fatal errors
}
