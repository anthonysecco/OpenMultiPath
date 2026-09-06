// Command ompd is the OpenMultiPath transport daemon. It carries traffic
// over every WAN link that is currently up, measures each one
// continuously, and records what it sees.
//
// It runs in one of two shapes. By default it sits below WireGuard,
// relaying already-encrypted packets from a loopback socket - the shape it
// was built with. Given -tun it sits above WireGuard instead, reading
// plaintext inner packets from a TUN device, which is what D-020 requires
// for classification to be possible at all. Both are kept so the move is
// reversible by restarting without the flag.
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
	"github.com/anthonysecco/OpenMultiPath/internal/linkdisco"
	"github.com/anthonysecco/OpenMultiPath/internal/relay"
)

// hostname names this box in the web interface, so the two ends are
// distinguishable without configuring anything.
func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

func main() {
	role := flag.String("role", "", "initiator (RV) or responder (home)")
	loopback := flag.String("loopback", "127.0.0.1:51900", "initiator only: local address WireGuard's peer Endpoint points at (this daemon listens here)")
	wgTarget := flag.String("wg-target", "127.0.0.1:51821", "responder only: local address WireGuard itself is listening on (its ListenPort)")
	paths := flag.String("paths", "", "initiator only: comma-separated interface names, e.g. enp1s0,enp2s0; each may be given as name=ip to pin a local address instead of discovering it. \"auto\" detects the WAN uplinks itself")
	lan := flag.String("lan", "10.0.0.0/24", "initiator only: the vehicle's own LAN subnet, excluded from -paths auto so the LAN side and the Wi-Fi lifeline are never taken for uplinks")
	remote := flag.String("remote", "", "initiator only: home's public endpoint, e.g. 162.231.243.253:48219")
	public := flag.String("public", "0.0.0.0:48219", "responder only: the forwarded public port to listen on")
	statePath := flag.String("state", "/var/lib/openmultipath/state.json", "where to write the snapshot the web interface reads")
	recordPath := flag.String("record", "/var/lib/openmultipath/history.jsonl", "where to append the rotating telemetry history; empty disables recording")
	usagePath := flag.String("usage", "/var/lib/openmultipath/usage.json", "initiator only: where to keep per-link billing-cycle totals; empty disables cost tracking")
	configPath := flag.String("config", "/etc/openmultipath/config.json", "adjustable settings, reloaded when the file changes")
	wgInterface := flag.String("wg-interface", "wg0", "tunnel interface, read for its current MTU")
	node := flag.String("node", hostname(), "this box's name, shown in the web interface")
	authKeyPath := flag.String("auth-key", "/etc/openmultipath/auth.key", "file holding the shared secret that authenticates the wire header; absent means unauthenticated")

	// D-020's data path, off by default. Naming a device moves the daemon
	// above WireGuard: it reads plaintext inner packets from the TUN
	// instead of ciphertext from WireGuard's loopback, which is what makes
	// classification possible at all. Leaving it empty keeps the loopback
	// relay the daemon was built with.
	//
	// Both shapes are kept deliberately. This is a flag day on a vehicle
	// that may be 800 miles away, and principle 5 wants the way back to be
	// one flag rather than a recovery trip - so the switch is a restart
	// with an argument removed, not a rollback to an older build.
	tunName := flag.String("tun", "", "D-020: run above WireGuard on this TUN device, e.g. omp0; empty keeps the loopback relay")
	tunAddr := flag.String("tun-addr", "", "tunnel address for -tun, in CIDR form, e.g. 10.30.0.2/24")
	tunMTU := flag.Int("tun-mtu", 1300, "MTU for -tun; must leave room for the wire header, UDP, IP and WireGuard inside the path MTU")
	flag.Parse()

	// A missing settings file is the normal case: every value has a
	// working default and the file only exists once something has been
	// changed through the web interface.
	settings, err := config.Load(*configPath)
	if err != nil {
		log.Printf("config: %v; continuing with defaults", err)
	}
	holder := config.NewHolder(settings)
	go holder.Watch(*configPath)

	// The shared secret lives in a file of its own, never in the settings
	// the web interface serves over HTTP. A missing file is not an error:
	// running unauthenticated is the current default, and a node that
	// refused to start without a key would make enabling authentication a
	// flag day rather than a rolling change.
	authKey, err := relay.LoadAuthKey(*authKeyPath)
	if err != nil {
		log.Fatalf("ompd: %v", err)
	}
	if len(authKey) > 0 {
		log.Printf("ompd: authenticating wire headers with the key in %s", *authKeyPath)
	}

	switch *role {
	case "initiator":
		cfg := relay.InitiatorConfig{
			LoopbackAddr: *loopback,
			RemoteAddr:   *remote,
			Paths:        resolvePaths(*paths, *lan, *wgInterface, *tunName),
			Node:         *node,
			StatePath:    *statePath,
			RecordPath:   *recordPath,
			UsagePath:    *usagePath,
			WGInterface:  *wgInterface,
			Settings:     holder,
			AuthKey:      authKey,
			Tun:          relay.TunConfig{Name: *tunName, Addr: *tunAddr, MTU: *tunMTU},
		}
		if err := relay.RunInitiator(cfg); err != nil {
			log.Fatal(err)
		}
	case "responder":
		cfg := relay.ResponderConfig{
			PublicAddr:     *public,
			LoopbackTarget: *wgTarget,
			Node:           *node,
			StatePath:      *statePath,
			RecordPath:     *recordPath,
			WGInterface:    *wgInterface,
			Settings:       holder,
			AuthKey:        authKey,
			Tun:            relay.TunConfig{Name: *tunName, Addr: *tunAddr, MTU: *tunMTU},
		}
		if err := relay.RunResponder(cfg); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("ompd: -role must be \"initiator\" or \"responder\", got %q", *role)
	}
}

// resolvePaths turns the -paths flag into a link list, auto-detecting the
// links when it is "auto" and parsing the names otherwise.
//
// Auto-detection is mode-aware, because "the links to build tunnels over"
// means two different things at the two layers this daemon can run at. Above
// WireGuard (D-020, -tun set) the daemon's paths are the wg transport tunnels
// - the physical NICs are a layer below, carrying the encryption - so auto
// selects those. In the loopback-relay shape the paths are the physical WAN
// uplinks, so auto selects those instead. Pointing one layer's daemon at the
// other layer's interfaces is how you strand the vehicle.
//
// Either way it is a starting-gun, not a running watch: it enumerates once,
// here, so a link that is genuinely down at boot is not detected this run.
// That is the same trade the manual list makes - a named link that is down is
// a path that is down, not an error - and once the daemon is up, linkwatch
// rediscovers addresses on the links it already knows. A link that appears
// for the first time after boot still has to be named; picking that up live
// is a larger change than this.
func resolvePaths(spec, lan, wg, tun string) []relay.PathConfig {
	if strings.TrimSpace(spec) != "auto" {
		return parsePaths(spec)
	}

	var (
		picked  []string
		reasons map[string]string
		err     error
	)
	if tun != "" {
		// Above WireGuard: the paths are the wg transports, and the
		// daemon's own tun is excluded so it cannot ride over itself.
		picked, reasons, err = linkdisco.DiscoverTransports(tun)
	} else {
		var lanNet *net.IPNet
		if lan != "" {
			_, n, e := net.ParseCIDR(lan)
			if e != nil {
				log.Fatalf("ompd: invalid -lan %q: %v", lan, e)
			}
			lanNet = n
		}
		picked, reasons, err = linkdisco.Discover(lanNet, wg)
	}
	if err != nil {
		log.Fatalf("ompd: -paths auto: %v", err)
	}

	// Say what was seen and why, both for the links taken and the ones
	// passed over, so "it did not use my modem" is answerable from the log
	// rather than by guessing at the heuristic.
	names := make([]string, 0, len(reasons))
	for name := range reasons {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		log.Printf("ompd: -paths auto: %s: %s", name, reasons[name])
	}

	if len(picked) == 0 {
		log.Fatalf("ompd: -paths auto found no WAN uplinks; name them with -paths instead")
	}
	log.Printf("ompd: -paths auto selected %s", strings.Join(picked, ", "))

	out := make([]relay.PathConfig, len(picked))
	for i, name := range picked {
		out[i] = relay.PathConfig{Name: name}
	}
	return out
}

// parsePaths reads the configured links. An entry is an interface name on
// its own, which is the normal case: the address is discovered from the
// interface and rediscovered whenever it changes. An entry may also be
// written name=ip to pin a specific local address.
//
// No address is looked up here. A link that is not up yet is a path that
// is currently down, not a configuration error, and deciding that at
// startup is exactly the mistake that stops the daemon from ever coming
// up on a cold boot.
func parsePaths(s string) []relay.PathConfig {
	var out []relay.PathConfig
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, bind, _ := strings.Cut(part, "=")
		name, bind = strings.TrimSpace(name), strings.TrimSpace(bind)
		if name == "" {
			log.Fatalf("ompd: invalid -paths entry %q, expected an interface name", part)
		}
		out = append(out, relay.PathConfig{Name: name, Bind: bind})
	}
	return out
}
