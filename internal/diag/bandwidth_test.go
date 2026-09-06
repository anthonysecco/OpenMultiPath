package diag

import (
	"strings"
	"testing"
)

// The run must be pinned to the named interface with --bind-dev, the way the
// daemon pins its own path sockets - source address alone does not select the
// tunnel here.
func TestArgsPinToInterface(t *testing.T) {
	got := strings.Join(Options{Iface: "wg2", Server: "10.20.1.1", Port: 5201, Seconds: 10}.Args(), " ")
	for _, want := range []string{"--bind-dev wg2", "-c 10.20.1.1", "-p 5201", "-t 10", "-J"} {
		if !strings.Contains(got, want) {
			t.Errorf("args %q missing %q", got, want)
		}
	}
	// No -P when streams is unset: that is a single stream.
	if strings.Contains(got, "-P") {
		t.Errorf("args %q has -P with no streams set", got)
	}
}

// Parallel streams are what make the tunnel test read the real capacity
// rather than a single stream's window-limited floor.
func TestArgsParallelStreams(t *testing.T) {
	got := strings.Join(Options{Iface: "wg1", Server: "10.20.1.1", Port: 5201, Seconds: 5, Streams: 8}.Args(), " ")
	if !strings.Contains(got, "-P 8") {
		t.Errorf("args %q missing -P 8", got)
	}
}

// A normal client report yields the uplink (sum_sent) rate in Mbps.
func TestParseUplinkRate(t *testing.T) {
	out := []byte(`{"end":{"sum_sent":{"bits_per_second":12500000,"retransmits":7,"seconds":10.0,"bytes":15625000}}}`)
	r, err := Parse(out)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.Mbps != 12.5 {
		t.Errorf("mbps = %v, want 12.5", r.Mbps)
	}
	if r.Retransmits != 7 {
		t.Errorf("retransmits = %d, want 7", r.Retransmits)
	}
}

// iperf3 reports a failed connection in the JSON body and exits non-zero;
// the message has to surface, not a bare "exit status 1".
func TestParseSurfacesIperfError(t *testing.T) {
	out := []byte(`{"error":"unable to connect to server: Connection refused"}`)
	_, err := Parse(out)
	if err == nil {
		t.Fatal("expected an error from an iperf error report")
	}
	if !strings.Contains(err.Error(), "Connection refused") {
		t.Errorf("error %q does not carry iperf's message", err)
	}
}

// Non-JSON output (iperf3 not installed, a shell error) is reported as such
// rather than panicking on the unmarshal.
func TestParseNonJSON(t *testing.T) {
	if _, err := Parse([]byte("iperf3: command not found")); err == nil {
		t.Fatal("expected an error from non-JSON output")
	}
}

// librespeed-cli prints a one-element array; the parser reads the first entry
// and carries the bytes moved, which are the cost of the test.
func TestParseSpeedtest(t *testing.T) {
	out := []byte(`[{"server":{"name":"Los Angeles, USA (Sharktech)"},"ping":41.18,"jitter":3.61,"upload":12.5,"download":118.62,"bytes_sent":8000000,"bytes_received":53397760}]`)
	r, err := ParseSpeedtest(out)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.DownloadMbps != 118.62 || r.UploadMbps != 12.5 {
		t.Errorf("rates = %v/%v, want 118.62/12.5", r.DownloadMbps, r.UploadMbps)
	}
	if r.PingMs != 41.18 {
		t.Errorf("ping = %v, want 41.18", r.PingMs)
	}
	if r.Server != "Los Angeles, USA (Sharktech)" {
		t.Errorf("server = %q", r.Server)
	}
	if r.BytesReceived != 53397760 {
		t.Errorf("bytes_received = %d", r.BytesReceived)
	}
}

// An empty array - no server was reachable over the pinned link - is an
// error, not a zero-valued success that would read as "0 Mbps".
func TestParseSpeedtestEmpty(t *testing.T) {
	if _, err := ParseSpeedtest([]byte(`[]`)); err == nil {
		t.Fatal("expected an error from an empty result")
	}
}

func TestParseSpeedtestNonJSON(t *testing.T) {
	if _, err := ParseSpeedtest([]byte("librespeed-cli: not found")); err == nil {
		t.Fatal("expected an error from non-JSON output")
	}
}

// A UDP flood adds -u and an unlimited -b 0 (iperf3's UDP default of 1 Mbit/s
// would flood nothing).
func TestArgsUDPFlood(t *testing.T) {
	got := strings.Join(Options{Iface: "wg1", Server: "10.20.1.1", Port: 5201, Seconds: 5, UDP: true}.Args(), " ")
	for _, want := range []string{"-u", "-b 0"} {
		if !strings.Contains(got, want) {
			t.Errorf("args %q missing %q", got, want)
		}
	}
}

// A UDP result reports what was delivered, what was offered to get it, and
// the loss and jitter above the wall - read from sum_received, not sum_sent.
func TestParseUDP(t *testing.T) {
	out := []byte(`{"start":{"test_start":{"protocol":"UDP"}},"end":{"sum_sent":{"bits_per_second":200000000,"bytes":125000000,"seconds":5.0},"sum_received":{"bits_per_second":48000000,"jitter_ms":0.8,"lost_percent":76.0}}}`)
	r, err := Parse(out)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.Protocol != "UDP" {
		t.Errorf("protocol = %q, want UDP", r.Protocol)
	}
	if r.Mbps != 48 {
		t.Errorf("delivered = %v Mbps, want 48", r.Mbps)
	}
	if r.OfferedMbps != 200 {
		t.Errorf("offered = %v Mbps, want 200", r.OfferedMbps)
	}
	if r.LossPercent != 76 {
		t.Errorf("loss = %v%%, want 76", r.LossPercent)
	}
}
