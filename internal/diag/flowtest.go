// flowtest.go is the "Measure Link Speed" button's implementation (D-040): an
// ompd-project-native raw-link UDP flood, with no external binary needed on
// either end.
//
// It answers what this tunnel's raw forwarding ceiling is, in each
// direction, and keeps a firm boundary: this never touches ompd's own
// classification or scheduling (internal/relay), it is not part of the
// estimator, and it only runs when a person presses the button. See D-053.
//
// A scheduler-pinned variant of this test once existed (force one flow onto
// one path via ompd's own classification, to see what the load balancer
// does with a path under load rather than what the raw link can carry) but
// was removed outright rather than ported to this protocol - see D-054.
//
// Protocol, deliberately minimal: one UDP socket per side, five message
// types, no jitter (RFC 3550 jitter needs many samples to mean anything and
// nothing here reads it - loss and throughput are what a flood test exists
// to produce). Each direction is measured in its own phase, sequentially,
// because concurrent up+down halves the flood each direction actually gets
// and complicates the accounting for no real benefit at these speeds.
//
//   - client -> server: start    {runID, direction, seconds}
//   - server -> client: startAck {runID}
//   - sender -> receiver: data   {runID, seq} x many, flat out, no pacing
//   - client -> server: reportReq{runID}
//   - server -> client: report   {runID, bytes, packets}
//     (upload: the server's own receive tally. download: the server's own
//     send tally, remembered once its flood loop ends.)
//
// reportReq/report is always client-initiated and retried, in both
// directions - an early draft had the server push the download report
// unprompted the instant its flood ended, which is exactly the moment a real
// link is most likely to drop it, and did on the first one this ran against.
//
// No target rate: an early draft paced sends to a configured Mbps, but a Go
// loop cannot hit five- or six-figure packets/sec pacing precisely - the
// sleeps needed are shorter than the scheduler can reliably honor - and an
// inaccurate pacer would silently under-read a fast
// path as its own bug rather than the link's real ceiling. Sending flat out
// has no such failure mode: every real path this project targets tops out
// two orders of magnitude below what a modern CPU can push over a socket, so
// "as fast as this process can write" is already far enough above any real
// ceiling to find it via the loss that appears there.
package diag

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net"
	"syscall"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

// FlowPacketSize is the UDP payload size used for the data phase of a flow
// test. Matches a typical path MTU so the test's per-packet cost looks like
// a real packet's, not a tiny control message's.
const FlowPacketSize = 1200

// Flow test message types. A single byte tag at the front of every packet.
const (
	msgStart     byte = 1
	msgStartAck  byte = 2
	msgData      byte = 3
	msgReportReq byte = 4
	msgReport    byte = 5
)

const (
	dirUpload   byte = 0 // client sends, server receives and reports
	dirDownload byte = 1 // server sends and reports, client receives
)

// flowGrace is how much longer a receiver keeps counting past the nominal
// test duration, to catch packets already in flight when the sender's loop
// ends.
const flowGrace = 400 * time.Millisecond

// Retry budget for the two control round trips (start/ack and
// reportReq/report). The report side gets more attempts: it must not reply
// until its own counting window (seconds+flowGrace) has closed, so the first
// few requests are expected to go unanswered rather than indicate loss.
const (
	ackAttempts    = 5
	ackInterval    = 300 * time.Millisecond
	reportAttempts = 12
	reportInterval = 300 * time.Millisecond
)

// interPhaseGap is the pause between the upload and download phases of one
// run, letting the first phase's flood drain off the link before the second
// one starts.
const interPhaseGap = 500 * time.Millisecond

func interPhaseWait(ctx context.Context) error {
	select {
	case <-time.After(interPhaseGap):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// FlowOptions describes one ompd-native flow test.
type FlowOptions struct {
	// Iface pins egress to one interface with SO_BINDTODEVICE - source
	// address alone does not select the tunnel here, see D-040.
	Iface   string
	Server  string // flowtest server address, e.g. "10.20.1.1"
	Port    int
	Seconds int // duration of each direction; total run time is roughly 2x this
}

// FlowResult is both directions of one run. Rates are the estimated physical
// wire rate - each packet's counted payload plus its known UDP/IPv4 and
// WireGuard framing overhead, see mbps - not the smaller
// payload-only rate a socket-level byte count would otherwise show. There is
// no jitter figure - dropped deliberately, see the package doc - and
// "offered" is always a real measured count (the sender's own tally), never
// an assumed target rate.
type FlowResult struct {
	UploadMbps          float64 `json:"upload_mbps"`
	UploadOfferedMbps   float64 `json:"upload_offered_mbps"`
	UploadLossPercent   float64 `json:"upload_loss_percent"`
	DownloadMbps        float64 `json:"download_mbps"`
	DownloadOfferedMbps float64 `json:"download_offered_mbps"`
	DownloadLossPercent float64 `json:"download_loss_percent"`
	Seconds             float64 `json:"seconds"`
}

// tally is one side's count of one phase - either what it sent or what it
// received, the two halves loss is computed from.
type tally struct {
	bytes   uint64
	packets uint64
}

// This test's own byte count is only ever the UDP payload it wrote or read -
// by the time either socket sees a data packet, the kernel has already
// stripped the framing that actually crossed the physical link. The goal
// here is the underlying link speed (D-053), not the tunnel's payload rate,
// so every packet's real wire cost is added back rather than reported as
// smaller than the carrier actually saw: its own UDP/IPv4 header, the
// padding WireGuard adds to a multiple of 16, WireGuard's 32 bytes of
// framing, and the outer UDP/IPv4 header that framing rides in.
//
// All of it applies because this test binds straight to the wg interface
// (D-040's own choice), so every data packet really is WireGuard-encapsulated
// on its way out. protocol.IPWireBytes is shared with ompd's shaper (D-055),
// which limits each link to 95% of this figure and has to count bytes exactly
// the way it was measured.
func mbps(t tally, seconds int) float64 {
	if seconds <= 0 || t.packets == 0 {
		return 0
	}
	// Every data packet is the same size, so one packet's cost stands for all.
	perPacket := protocol.IPWireBytes(int(t.bytes/t.packets), true)
	return float64(t.packets*uint64(perPacket)) * 8 / 1e6 / float64(seconds)
}

func lossPercent(sent, received tally) float64 {
	if sent.packets == 0 || received.packets >= sent.packets {
		return 0
	}
	return (1 - float64(received.packets)/float64(sent.packets)) * 100
}

// RunFlowTest runs both directions against a flowtest server (cmd/omp-flowtest)
// and returns the combined result.
func RunFlowTest(ctx context.Context, o FlowOptions) (FlowResult, error) {
	seconds := o.Seconds
	if seconds < 1 {
		seconds = 5
	}

	conn, err := listenOnDevice(o.Iface)
	if err != nil {
		return FlowResult{}, fmt.Errorf("flowtest: binding to %s: %w", o.Iface, err)
	}
	defer conn.Close()

	serverIP := net.ParseIP(o.Server)
	if serverIP == nil {
		return FlowResult{}, fmt.Errorf("flowtest: bad server address %q", o.Server)
	}
	server := &net.UDPAddr{IP: serverIP, Port: o.Port}

	runID := rand.Uint64()
	upSent, upRecv, err := uploadPhase(ctx, conn, server, runID, seconds)
	if err != nil {
		return FlowResult{}, fmt.Errorf("flowtest upload: %w", err)
	}

	// A pause between phases: the first phase's flood leaves the link's own
	// queue draining (see floodSend's doc comment on write blocking under
	// real backpressure), and starting the second phase's flood straight
	// into that gives a skewed reading of the second direction rather than a
	// clean one.
	if err := interPhaseWait(ctx); err != nil {
		return FlowResult{}, err
	}

	// A different run id for the second phase, purely so a stray retransmit
	// from the first phase can never be mistaken for data in the second.
	downSent, downRecv, err := downloadPhase(ctx, conn, server, runID+1, seconds)
	if err != nil {
		return FlowResult{}, fmt.Errorf("flowtest download: %w", err)
	}

	return FlowResult{
		UploadMbps:          mbps(upRecv, seconds),
		UploadOfferedMbps:   mbps(upSent, seconds),
		UploadLossPercent:   lossPercent(upSent, upRecv),
		DownloadMbps:        mbps(downRecv, seconds),
		DownloadOfferedMbps: mbps(downSent, seconds),
		DownloadLossPercent: lossPercent(downSent, downRecv),
		Seconds:             float64(seconds),
	}, nil
}

// uploadPhase floods the server and asks it what arrived. The client's own
// send tally needs no wire trip - it is already known locally.
func uploadPhase(ctx context.Context, conn *net.UDPConn, server *net.UDPAddr, runID uint64, seconds int) (sent, received tally, err error) {
	if err := startAndWaitAck(ctx, conn, server, runID, dirUpload, seconds); err != nil {
		return tally{}, tally{}, err
	}
	sent = floodSend(ctx, conn, server, runID, time.Duration(seconds)*time.Second)
	received, err = requestReport(ctx, conn, server, runID)
	if err != nil {
		return tally{}, tally{}, err
	}
	return sent, received, nil
}

// downloadPhase asks the server to flood back, counts what arrives locally,
// then asks the server what it sent - the same reportReq/report round trip
// uploadPhase uses, and for the same reason: a lone unprompted report packet
// fired the instant a saturating flood ends is exactly the moment most
// likely to lose it, which is what an earlier version of this code did and
// what actually happened on the first real link it was tried against.
func downloadPhase(ctx context.Context, conn *net.UDPConn, server *net.UDPAddr, runID uint64, seconds int) (sent, received tally, err error) {
	if err := startAndWaitAck(ctx, conn, server, runID, dirDownload, seconds); err != nil {
		return tally{}, tally{}, err
	}
	received = countIncoming(ctx, conn, runID, time.Duration(seconds)*time.Second+flowGrace)
	sent, err = requestReport(ctx, conn, server, runID)
	if err != nil {
		return tally{}, tally{}, err
	}
	return sent, received, nil
}

// sendUntilMatch resends req every interval until a packet satisfying match
// arrives, for a total wall-clock budget of attempts*interval.
//
// The budget is wall-clock, not a count of read attempts, on purpose: this
// socket can still be receiving stray trailing data from a flood that just
// finished (see floodSend's doc comment) while a control reply is awaited.
// Each such packet completes a read instantly without matching, so counting
// "attempts" would let a burst of stray packets exhaust the whole retry
// budget in milliseconds instead of the seconds it was meant to cover -
// exactly what made the second real-link attempt at this protocol still
// fail after the write-deadline fix alone.
func sendUntilMatch(ctx context.Context, conn *net.UDPConn, dst *net.UDPAddr, req []byte, attempts int, interval time.Duration, match func(buf []byte, n int) bool) ([]byte, error) {
	buf := make([]byte, FlowPacketSize+64)
	deadline := time.Now().Add(time.Duration(attempts) * interval)
	var nextSend time.Time
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, fmt.Errorf("no matching response within %v", time.Duration(attempts)*interval)
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !time.Now().Before(nextSend) {
			// A write deadline here too: a control message sent right after
			// a flood on the same socket can still hit a queue the flood
			// only just finished filling. Best-effort - a failed send just
			// means this resend is skipped, the next one still fires.
			conn.SetWriteDeadline(time.Now().Add(interval))
			conn.WriteToUDP(req, dst)
			nextSend = time.Now().Add(interval)
		}
		wait := interval
		if remaining < wait {
			wait = remaining
		}
		conn.SetReadDeadline(time.Now().Add(wait))
		n, _, err := conn.ReadFromUDP(buf)
		if err == nil && match(buf, n) {
			return buf[:n], nil
		}
	}
}

func startAndWaitAck(ctx context.Context, conn *net.UDPConn, server *net.UDPAddr, runID uint64, dir byte, seconds int) error {
	req := make([]byte, 12)
	req[0] = msgStart
	binary.BigEndian.PutUint64(req[1:9], runID)
	req[9] = dir
	binary.BigEndian.PutUint16(req[10:12], uint16(seconds))

	_, err := sendUntilMatch(ctx, conn, server, req, ackAttempts, ackInterval, func(buf []byte, n int) bool {
		return n >= 9 && buf[0] == msgStartAck && binary.BigEndian.Uint64(buf[1:9]) == runID
	})
	if err != nil {
		return fmt.Errorf("no response from flowtest server at %s (is omp-flowtest running there?)", server)
	}
	return nil
}

// floodSend writes as fast as the socket will accept for dur, with no rate
// target - see the package doc for why pacing to an exact Mbps was dropped.
//
// The write deadline is load-bearing, not defensive: the first real-link run
// (AT&T, path 0, 2026-09-13) showed the download phase still transmitting
// data more than five seconds after a 5-second flood was requested - loopback
// never blocks a write, so this only ever showed up off the bench. A slow
// uplink makes WireGuard's own transmit queue for that peer back up, and
// Write blocks waiting for room rather than failing fast, so the
// `time.Now().Before(deadline)` check between writes never gets a chance to
// fire - it can only run after the *current* write returns, and an unbounded
// write can return arbitrarily late. Bounding the write itself with the same
// deadline turns a stalled write into a fast, expected error right when the
// window closes, instead of the whole function running for however long the
// kernel felt like blocking.
func floodSend(ctx context.Context, conn *net.UDPConn, dst *net.UDPAddr, runID uint64, dur time.Duration) tally {
	payload := make([]byte, FlowPacketSize)
	payload[0] = msgData
	binary.BigEndian.PutUint64(payload[1:9], runID)

	var t tally
	var seq uint64
	deadline := time.Now().Add(dur)
	conn.SetWriteDeadline(deadline)
	// Cleared rather than left expired: this socket is reused for control
	// messages afterward (an ack, a report reply), and a write deadline that
	// already passed would fail every one of them instantly.
	defer conn.SetWriteDeadline(time.Time{})

	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			break
		}
		binary.BigEndian.PutUint64(payload[9:17], seq)
		n, err := conn.WriteToUDP(payload, dst)
		if err != nil {
			continue
		}
		t.bytes += uint64(n)
		t.packets++
		seq++
	}
	return t
}

// requestReport asks the server how much it sent or received for runID
// (whichever direction that run was). The server only answers once its own
// counting or sending is done, so early attempts are expected to go
// unanswered rather than indicate anything is wrong.
func requestReport(ctx context.Context, conn *net.UDPConn, server *net.UDPAddr, runID uint64) (tally, error) {
	req := make([]byte, 9)
	req[0] = msgReportReq
	binary.BigEndian.PutUint64(req[1:9], runID)

	reply, err := sendUntilMatch(ctx, conn, server, req, reportAttempts, reportInterval, func(buf []byte, n int) bool {
		return n >= 25 && buf[0] == msgReport && binary.BigEndian.Uint64(buf[1:9]) == runID
	})
	if err != nil {
		return tally{}, fmt.Errorf("flowtest server never reported its count for this run")
	}
	return tally{
		bytes:   binary.BigEndian.Uint64(reply[9:17]),
		packets: binary.BigEndian.Uint64(reply[17:25]),
	}, nil
}

// countIncoming counts msgData for runID until dur has elapsed. Used for the
// download phase's receive side - the client's own tally, needing no wire
// trip, symmetric to how uploadPhase already knows its own send tally
// locally.
func countIncoming(ctx context.Context, conn *net.UDPConn, runID uint64, dur time.Duration) tally {
	buf := make([]byte, FlowPacketSize+64)
	deadline := time.Now().Add(dur)
	var received tally
	for {
		if ctx.Err() != nil {
			return received
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return received
		}
		conn.SetReadDeadline(time.Now().Add(remaining))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return received // deadline reached
		}
		if n < 9 || binary.BigEndian.Uint64(buf[1:9]) != runID || buf[0] != msgData {
			continue
		}
		received.bytes += uint64(n)
		received.packets++
	}
}

// listenOnDevice opens a UDP socket pinned to a physical/transport interface
// with SO_BINDTODEVICE - the same technique internal/relay/paths.go uses for
// the daemon's own per-path sockets, duplicated here rather than exported
// from internal/relay so this diagnostic package still has no dependency on
// the daemon's own code. An empty iface is left un-pinned - only the
// flowtest server, which has no single path to prefer, uses that.
func listenOnDevice(iface string) (*net.UDPConn, error) {
	if iface == "" {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{})
		if err != nil {
			return nil, err
		}
		setFlowReadBuffer(conn)
		return conn, nil
	}
	var controlErr error
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				controlErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
			})
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	if controlErr != nil {
		pc.Close()
		return nil, fmt.Errorf("SO_BINDTODEVICE %s: %w", iface, controlErr)
	}
	conn := pc.(*net.UDPConn)
	setFlowReadBuffer(conn)
	return conn, nil
}

// flowReadBufferBytes is set on every flowtest socket, sender and receiver
// alike. The default kernel UDP receive buffer (a few hundred KB) fills in
// well under a millisecond at flood rates, and packets dropped there read as
// "the link's ceiling" indistinguishably from packets the link itself
// dropped - which would understate every path this test is meant to measure
// honestly. Sized generously since the cost is a one-time allocation, not a
// per-packet one.
const flowReadBufferBytes = 4 << 20 // 4 MiB

func setFlowReadBuffer(conn *net.UDPConn) {
	// Best-effort: a platform or sandbox that refuses SO_RCVBUF still leaves
	// the test working, just more exposed to the buffer-overflow artifact
	// above - not a reason to fail the run.
	_ = conn.SetReadBuffer(flowReadBufferBytes)
}

// ServeFlowTest runs the home-end listener forever on an already-open
// socket, handling one run at a time - the same single-flight assumption
// ompui's diagMu already enforces from the client side. It never returns
// until ctx is done or the socket fails. Listening is the caller's job
// (cmd/omp-flowtest binds the fixed transport-hub address; tests bind an
// ephemeral loopback port), so this has no address to fail to parse.
func ServeFlowTest(ctx context.Context, conn *net.UDPConn) error {
	setFlowReadBuffer(conn)

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	// activeUpload is the run currently being counted, if the last msgStart
	// was an upload - reportReq must not answer for it until its own
	// deadline has passed, since the tally is still being added to.
	type activeUpload struct {
		runID    uint64
		deadline time.Time
		tally    tally
	}
	var up *activeUpload

	// completed is the most recent run this server can answer reportReq
	// for: either an upload once its counting window closes, or a download
	// as soon as this server's own flood finishes sending. One slot, not a
	// map, because ompui's diagMu makes this single-flight from the client
	// side - there is never more than one run worth remembering.
	type completed struct {
		runID uint64
		tally tally
	}
	var done completed

	// This server runs one long-lived read loop for every future run, not
	// just the current one - a write that blocked indefinitely here would
	// wedge every run after it, not merely this one. A short, bounded
	// deadline on every control write keeps a single bad link from taking
	// the whole server down with it (principle 5).
	const controlWriteTimeout = 1 * time.Second

	sendReport := func(peer *net.UDPAddr, runID uint64, t tally) {
		report := make([]byte, 25)
		report[0] = msgReport
		binary.BigEndian.PutUint64(report[1:9], runID)
		binary.BigEndian.PutUint64(report[9:17], t.bytes)
		binary.BigEndian.PutUint64(report[17:25], t.packets)
		conn.SetWriteDeadline(time.Now().Add(controlWriteTimeout))
		conn.WriteToUDP(report, peer)
	}

	buf := make([]byte, FlowPacketSize+64)
	for {
		n, peer, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		if n < 9 {
			continue
		}
		typ := buf[0]
		runID := binary.BigEndian.Uint64(buf[1:9])

		switch typ {
		case msgStart:
			if n < 12 {
				continue
			}
			dir := buf[9]
			seconds := binary.BigEndian.Uint16(buf[10:12])

			ack := make([]byte, 9)
			ack[0] = msgStartAck
			binary.BigEndian.PutUint64(ack[1:9], runID)
			conn.SetWriteDeadline(time.Now().Add(controlWriteTimeout))
			conn.WriteToUDP(ack, peer)

			if dir == dirDownload {
				// The server is the sender for this phase. Flood now, then
				// just remember what was sent - the client asks for it via
				// the same retried reportReq the upload phase uses, rather
				// than this pushing one unprompted packet at the exact
				// moment (right after saturating the link) it is likeliest
				// to be lost. That happened on the first real link this was
				// tried against.
				up = nil
				sent := floodSend(ctx, conn, peer, runID, time.Duration(seconds)*time.Second)
				done = completed{runID: runID, tally: sent}
			} else {
				up = &activeUpload{
					runID:    runID,
					deadline: time.Now().Add(time.Duration(seconds)*time.Second + flowGrace),
				}
			}

		case msgData:
			if up != nil && up.runID == runID && time.Now().Before(up.deadline) {
				up.tally.bytes += uint64(n)
				up.tally.packets++
			}

		case msgReportReq:
			if up != nil && up.runID == runID && !time.Now().Before(up.deadline) {
				done = completed{runID: up.runID, tally: up.tally}
				sendReport(peer, runID, done.tally)
			} else if done.runID == runID {
				sendReport(peer, runID, done.tally)
			}
		}
	}
}
