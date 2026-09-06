// Package diag runs on-demand link diagnostics that are deliberately kept
// out of the daemon's own measurement path.
//
// The bandwidth estimator (D-023) infers capacity passively, from traffic
// that was going to be sent anyway, and never spends the link to measure it.
// That is the right default for a metered link on the road, but it means the
// number is only ever as good as the load that has happened to flow, and
// there is no way to check it against ground truth. This is that check: an
// operator-triggered iperf3 run over one path, for comparing the estimate to
// a real saturating transfer. It is not wired into scheduling and never runs
// on its own - it costs uplink data, which on a metered link is the whole
// reason the estimator avoids active probing in the first place.
//
// The run is pinned to a single path with SO_BINDTODEVICE (iperf3's
// --bind-dev), exactly as the daemon pins its own per-path sockets - source
// address alone does not pin egress here, since the kernel routes every
// transport address out the first tunnel regardless.
package diag

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
)

// Options describes one uplink test.
type Options struct {
	Iface   string // the interface to pin egress to, e.g. "wg1"
	Server  string // iperf3 server address, e.g. "10.20.1.1"
	Port    int    // iperf3 server port
	Seconds int    // test duration
}

// Args is the iperf3 command line for these options. Split out from the run
// so the invocation can be asserted in a test without a server to talk to.
func (o Options) Args() []string {
	return []string{
		"-c", o.Server,
		"-p", strconv.Itoa(o.Port),
		"-t", strconv.Itoa(o.Seconds),
		"--bind-dev", o.Iface,
		"-J",
	}
}

// Result is the outcome of a run, in the units the interface shows.
type Result struct {
	Mbps        float64 `json:"mbps"`
	Retransmits int     `json:"retransmits"`
	Seconds     float64 `json:"seconds"`
	Bytes       int64   `json:"bytes"`
}

// iperfReport is the slice of iperf3's -J output that matters. sum_sent is
// the client's transmit side, which is the uplink under test.
type iperfReport struct {
	Error string `json:"error"`
	End   struct {
		SumSent struct {
			BitsPerSecond float64 `json:"bits_per_second"`
			Retransmits   int     `json:"retransmits"`
			Seconds       float64 `json:"seconds"`
			Bytes         int64   `json:"bytes"`
		} `json:"sum_sent"`
	} `json:"end"`
}

// Parse turns iperf3 -J output into a Result. iperf3 prints a JSON object
// with a populated "error" field and exits non-zero when it cannot connect,
// so the error travels in the output rather than only in the exit status.
func Parse(out []byte) (Result, error) {
	var rep iperfReport
	if err := json.Unmarshal(out, &rep); err != nil {
		return Result{}, fmt.Errorf("iperf3 output was not JSON (is iperf3 installed?): %w", err)
	}
	if rep.Error != "" {
		return Result{}, fmt.Errorf("iperf3: %s", rep.Error)
	}
	return Result{
		Mbps:        rep.End.SumSent.BitsPerSecond / 1e6,
		Retransmits: rep.End.SumSent.Retransmits,
		Seconds:     rep.End.SumSent.Seconds,
		Bytes:       rep.End.SumSent.Bytes,
	}, nil
}

// Run executes iperf3 for one uplink test and parses the result. The output
// is read even when iperf3 exits non-zero, because that is exactly the case
// - a refused connection, a missing server - where the useful message is in
// the JSON rather than the status.
func Run(ctx context.Context, o Options) (Result, error) {
	out, runErr := exec.CommandContext(ctx, "iperf3", o.Args()...).Output()

	// Prefer whatever the JSON says: iperf3's own "error" is more specific
	// than "exit status 1", and a clean run parses regardless of runErr.
	res, parseErr := Parse(out)
	if parseErr == nil {
		return res, nil
	}
	if runErr != nil {
		if ctx.Err() != nil {
			return Result{}, fmt.Errorf("iperf3 did not finish in time: %w", ctx.Err())
		}
		return Result{}, fmt.Errorf("iperf3 failed to run: %w", runErr)
	}
	return Result{}, parseErr
}
