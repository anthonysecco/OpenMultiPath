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
