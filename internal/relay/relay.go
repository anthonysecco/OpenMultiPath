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
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
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
			// A closed socket is how a path is deliberately retired when
			// its link goes away or its address moves, and the caller has
			// already said so. Only an unexpected failure is worth a line.
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("%s: read error: %v", name, err)
			}
			return
		}
		handle(buf[:n], from)
	}
}

// LoadAuthKey reads the shared secret that authenticates the wire header.
//
// A missing file yields no key and no error. That is deliberate: the daemon
// has to be able to run before anyone has provisioned a secret, and every
// node in the field today is running without one.
//
// Note what this does *not* buy. Installing the key is still a flag day:
// once one end has it, that end rejects the other's untagged version 2
// packets, so both have to be restarted together. The code upgrade rolls
// out safely one end at a time - see protocol.Version - but turning
// authentication on does not. It is a parked-in-the-driveway change, and
// the provisioning bundle is where it belongs, so that a unit is built with
// its key rather than having one added later.
//
// Whitespace is trimmed so a key file written by a shell redirect, which
// leaves a trailing newline, produces the same key at both ends. That has
// bitten enough projects to be worth the two lines.
func LoadAuthKey(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("relay: read auth key %s: %w", path, err)
	}
	key := bytes.TrimSpace(b)
	if len(key) == 0 {
		return nil, nil
	}
	if len(key) < minAuthKeyLen {
		return nil, fmt.Errorf("relay: auth key in %s is %d bytes, want at least %d",
			path, len(key), minAuthKeyLen)
	}
	return key, nil
}

// minAuthKeyLen rejects a key short enough to be guessed. The provisioning
// flow generates a long random one; this only catches a hand-typed
// placeholder that would give the appearance of authentication without any.
const minAuthKeyLen = 16
