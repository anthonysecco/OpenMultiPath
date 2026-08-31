// Command ompd is the OpenMultiPath transport daemon. It currently only
// implements the blind-duplication relay described in internal/relay;
// header-based sequencing, measurement and path selection land on top of
// this in later steps.
package main

import (
	"flag"
	"log"
	"strings"

	"github.com/anthonysecco/OpenMultiPath/internal/relay"
)

func main() {
	role := flag.String("role", "", "initiator (RV) or responder (home)")
	loopback := flag.String("loopback", "127.0.0.1:51900", "initiator only: local address WireGuard's peer Endpoint points at (this daemon listens here)")
	wgTarget := flag.String("wg-target", "127.0.0.1:51821", "responder only: local address WireGuard itself is listening on (its ListenPort)")
	paths := flag.String("paths", "", "initiator only: comma-separated name=bind-ip pairs, e.g. enp1s0=100.110.247.30,enp2s0=192.168.225.3")
	remote := flag.String("remote", "", "initiator only: home's public endpoint, e.g. 162.231.243.253:48219")
	public := flag.String("public", "0.0.0.0:48219", "responder only: the forwarded public port to listen on")
	flag.Parse()

	switch *role {
	case "initiator":
		cfg := relay.InitiatorConfig{
			LoopbackAddr: *loopback,
			RemoteAddr:   *remote,
			Paths:        parsePaths(*paths),
		}
		if err := relay.RunInitiator(cfg); err != nil {
			log.Fatal(err)
		}
	case "responder":
		cfg := relay.ResponderConfig{
			PublicAddr:     *public,
			LoopbackTarget: *wgTarget,
		}
		if err := relay.RunResponder(cfg); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("ompd: -role must be \"initiator\" or \"responder\", got %q", *role)
	}
}

func parsePaths(s string) []relay.PathConfig {
	var out []relay.PathConfig
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, bind, ok := strings.Cut(part, "=")
		if !ok {
			log.Fatalf("ompd: invalid -paths entry %q, expected name=bind-ip", part)
		}
		out = append(out, relay.PathConfig{Name: name, Bind: bind})
	}
	return out
}
