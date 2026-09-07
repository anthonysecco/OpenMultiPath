// Package pep is a single-sided split-TCP performance-enhancing proxy.
//
// Why it exists (D-043). A LAN client's TCP runs end to end, so its congestion
// control - often cubic - belongs to the client, not to us, and cubic
// collapses on the cellular uplink's non-congestive loss: on the vehicle a
// cubic client uploaded ~27 Mbps over a link a loss-tolerant sender fills at
// ~100. We cannot change the client. So the proxy terminates the client's TCP
// here, on the clean LAN, and re-opens the connection from this host, where
// BBR (D-041) carries it across the lossy WAN. The client is untouched;
// prototyped on the vehicle, a cubic client's upload went 27 -> ~100 Mbps.
//
// It is single-sided - only the vehicle runs it - because the re-opened
// connection is this host's and rides this host's BBR the whole way to the
// server. Connections arrive redirected by nftables/iptables (see
// deploy/omp-pep-rules); the original destination is recovered with
// SO_ORIGINAL_DST. The proxy's own dials are locally generated, so they go
// through OUTPUT rather than the PREROUTING redirect - there is no loop.
//
// It only helps TCP. QUIC and other UDP are not redirected and are left to
// their own congestion control, which is already loss-tolerant. It also trades
// away strict end-to-end TCP semantics (the client is acked by this host
// before the far end has the data), which is the accepted cost of any PEP and
// is fine for the bulk traffic this exists to speed up.
package pep

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// soOriginalDst is the getsockopt that returns the pre-redirect destination
// that netfilter stashed in conntrack.
const soOriginalDst = 80

// dialTimeout bounds how long a re-opened connection waits to establish before
// the client's attempt is abandoned.
const dialTimeout = 15 * time.Second

// decodeOriginalDst reads an IPv4 sockaddr_in out of the buffer SO_ORIGINAL_DST
// fills: family in host order, port in network order, then the address.
func decodeOriginalDst(m [16]byte) (netip.AddrPort, error) {
	if fam := binary.LittleEndian.Uint16(m[0:2]); fam != syscall.AF_INET {
		return netip.AddrPort{}, fmt.Errorf("original dst is not IPv4 (family %d)", fam)
	}
	port := binary.BigEndian.Uint16(m[2:4])
	addr := netip.AddrFrom4([4]byte{m[4], m[5], m[6], m[7]})
	return netip.AddrPortFrom(addr, port), nil
}

func originalDst(c *net.TCPConn) (netip.AddrPort, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var m [16]byte
	var ctlErr error
	if err := raw.Control(func(fd uintptr) {
		mreq, e := syscall.GetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IP, soOriginalDst)
		if e != nil {
			ctlErr = e
			return
		}
		m = mreq.Multiaddr
	}); err != nil {
		return netip.AddrPort{}, err
	}
	if ctlErr != nil {
		return netip.AddrPort{}, ctlErr
	}
	return decodeOriginalDst(m)
}

func handle(client *net.TCPConn) {
	defer client.Close()
	dst, err := originalDst(client)
	if err != nil {
		log.Printf("pep: original destination unreadable (was this connection redirected?): %v", err)
		return
	}
	server, err := net.DialTimeout("tcp", dst.String(), dialTimeout)
	if err != nil {
		log.Printf("pep: dial %s: %v", dst, err)
		return
	}
	srv := server.(*net.TCPConn)
	defer srv.Close()

	done := make(chan struct{}, 2)
	go splice(srv, client, done)
	go splice(client, srv, done)
	<-done
	<-done
}

// splice copies one direction and half-closes the destination when the source
// is done, so a one-way close (a finished upload) does not tear down the reply
// path before its data has drained.
func splice(dst, src *net.TCPConn, done chan<- struct{}) {
	io.Copy(dst, src)
	dst.CloseWrite()
	done <- struct{}{}
}

// Serve accepts redirected connections on ln until it errors permanently.
func Serve(ln *net.TCPListener) error {
	for {
		c, err := ln.AcceptTCP()
		if err != nil {
			return err
		}
		go handle(c)
	}
}

// Run listens on addr and serves. It is the whole of the command.
func Run(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("pep: split-TCP accelerator listening on %s", addr)
	return Serve(l.(*net.TCPListener))
}
