package diag

import (
	"context"
	"net"
	"testing"
	"time"
)

// startTestServer runs ServeFlowTest on an ephemeral loopback port and
// returns its address, cleaning up when the test ends.
func startTestServer(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go ServeFlowTest(ctx, conn)
	t.Cleanup(func() {
		cancel()
		conn.Close()
	})
	return conn.LocalAddr().(*net.UDPAddr)
}

// A full run against a real (loopback) server should see next to no loss in
// either direction - this is the same-box happy path a bad protocol
// implementation would still fail on.
func TestRunFlowTestLoopback(t *testing.T) {
	addr := startTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := RunFlowTest(ctx, FlowOptions{
		Server:  addr.IP.String(),
		Port:    addr.Port,
		Seconds: 1,
	})
	if err != nil {
		t.Fatalf("RunFlowTest: %v", err)
	}

	if res.UploadMbps <= 0 {
		t.Errorf("upload mbps = %v, want > 0", res.UploadMbps)
	}
	if res.DownloadMbps <= 0 {
		t.Errorf("download mbps = %v, want > 0", res.DownloadMbps)
	}
	if res.UploadLossPercent > 5 {
		t.Errorf("upload loss = %v%%, want near 0 on loopback", res.UploadLossPercent)
	}
	if res.DownloadLossPercent > 5 {
		t.Errorf("download loss = %v%%, want near 0 on loopback", res.DownloadLossPercent)
	}
	if res.Seconds != 1 {
		t.Errorf("seconds = %v, want 1", res.Seconds)
	}
}

// No server listening at all should fail fast with a clear error rather than
// hang for the full retry budget silently.
func TestRunFlowTestNoServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Nothing is listening on this loopback port.
	unused, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := unused.LocalAddr().(*net.UDPAddr)
	unused.Close()

	if _, err := RunFlowTest(ctx, FlowOptions{Server: addr.IP.String(), Port: addr.Port, Seconds: 1}); err == nil {
		t.Fatal("expected an error with no server listening")
	}
}

// lossPercent and mbps are the arithmetic the whole protocol exists to feed;
// worth pinning directly rather than only through the loopback integration
// test above.
func TestLossPercent(t *testing.T) {
	cases := []struct {
		name           string
		sent, received tally
		want           float64
	}{
		{"no loss", tally{packets: 100, bytes: 100}, tally{packets: 100, bytes: 100}, 0},
		{"half lost", tally{packets: 100}, tally{packets: 50}, 50},
		{"nothing sent", tally{packets: 0}, tally{packets: 0}, 0},
		{"more received than sent counted as no loss", tally{packets: 100}, tally{packets: 105}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := lossPercent(c.sent, c.received); got != c.want {
				t.Errorf("lossPercent(%+v, %+v) = %v, want %v", c.sent, c.received, got, c.want)
			}
		})
	}
}

func TestMbps(t *testing.T) {
	// 10,000 packets of 1200 bytes is 1292 bytes each on the wire, over
	// 2 seconds.
	got := mbps(tally{bytes: 12_000_000, packets: 10_000}, 2)
	if want := 1292.0 * 10_000 * 8 / 1e6 / 2; got != want {
		t.Errorf("mbps = %v, want %v", got, want)
	}
	if mbps(tally{bytes: 1000, packets: 1}, 0) != 0 {
		t.Errorf("mbps with 0 seconds should not divide by zero")
	}
	if mbps(tally{}, 1) != 0 {
		t.Errorf("mbps with nothing counted should be 0")
	}
}

// The reported rate is the estimated physical-link rate, not the raw
// application payload rate a naive byte count would give - each packet's
// UDP/IPv4 header, WireGuard padding and framing, and outer UDP/IPv4 header
// (all invisible to the socket-level byte count) are added back, per D-053.
func TestMbpsAddsWireOverhead(t *testing.T) {
	// One packet of FlowPacketSize payload in one second: 1200 + 28 = 1228,
	// padded to 1232, plus 32 of WireGuard and 28 of outer UDP/IPv4.
	got := mbps(tally{bytes: FlowPacketSize, packets: 1}, 1)
	want := float64(1292) * 8 / 1e6
	if got != want {
		t.Errorf("mbps = %v, want %v (1292 bytes on the wire per 1200-byte packet)", got, want)
	}
}

// An unpinned client (empty Iface) still has to be able to open a socket -
// this is the path both the tests above and a plain LAN box without a wg
// interface exercise.
func TestListenOnDeviceEmptyIface(t *testing.T) {
	conn, err := listenOnDevice("")
	if err != nil {
		t.Fatalf("listenOnDevice(\"\"): %v", err)
	}
	defer conn.Close()
}
