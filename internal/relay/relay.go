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
	"syscall"

	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

// ipPMTUDiscProbe is IP_PMTUDISC_PROBE from the kernel's linux/in.h. Go's
// syscall package does not name it.
const ipPMTUDiscProbe = 3

// setDontFragment marks a socket so its packets are never fragmented.
//
// Without this an oversized probe is simply split by the kernel and
// reassembled at the far end, so it "arrives" and confirms an MTU the path
// cannot actually carry in one piece - which is measuring reassembly, not
// path MTU. It also holds the line architecture.md draws about never
// relying on IP fragmentation, since carriers drop fragments
// unpredictably.
//
// PROBE rather than DO: it additionally ignores the kernel's cached path
// MTU, so a probe goes out on the wire and is dropped by whatever cannot
// carry it, instead of being pre-empted locally on a stale cached figure.
func setDontFragment(fd int) error {
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, ipPMTUDiscProbe)
}

const bufSize = 2048

// maxHeaderLen is the headroom reserved for the wire header when building
// an outgoing packet, so the scratch buffer never has to grow.
const maxHeaderLen = protocol.MaxHeaderLen

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
