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
	Streams int    // parallel TCP streams; <=1 runs a single stream

	// UDP runs a UDP flood instead of a TCP transfer. TargetMbps caps the
	// send rate; 0 means unlimited - a true flood that sends as fast as the
	// sender can and finds the wall by where loss appears. TCP measures what
	// gets through after backing off; UDP measures the raw forwarding
	// ceiling and the loss above it, which TCP can never show because it
	// never overshoots for long.
	UDP        bool
	TargetMbps int

	// Bytes, when > 0, transfers a fixed amount of data rather than running
	// for Seconds - an equal-payload comparison against a tool that moved a
	// known number of bytes, rather than an equal-time one. The duration
	// then falls out of the rate, which is the point: the same payload over
	// a slower path simply takes longer.
	Bytes int64
}

// Args is the iperf3 command line for these options. Split out from the run
// so the invocation can be asserted in a test without a server to talk to.
//
// Parallel streams matter here: a single TCP stream over the tunnel's RTT and
// smaller MSS is window-limited and reads far below the link's real capacity -
// on the vehicle a single stream measured 5 Mbps where eight measured 30 on
// the same path. The scheduler carries many flows at once, so the aggregate a
// handful of streams reveals is the honest figure to compare against.
func (o Options) Args() []string {
	args := []string{
		"-c", o.Server,
		"-p", strconv.Itoa(o.Port),
		"--bind-dev", o.Iface,
		"-J",
	}
	if o.Bytes > 0 {
		// -n is the total to transfer across all streams (verified on
		// iperf3 3.18), and is mutually exclusive with -t; the run stops
		// when the bytes are sent, however long that takes.
		args = append(args, "-n", strconv.FormatInt(o.Bytes, 10))
	} else {
		args = append(args, "-t", strconv.Itoa(o.Seconds))
	}
	if o.UDP {
		// -b 0 is unlimited; iperf3's UDP default is a gentle 1 Mbit/s,
		// which would not flood anything.
		rate := "0"
		if o.TargetMbps > 0 {
			rate = strconv.Itoa(o.TargetMbps) + "M"
		}
		args = append(args, "-u", "-b", rate)
	}
	if o.Streams > 1 {
		args = append(args, "-P", strconv.Itoa(o.Streams))
	}
	return args
}

// Result is the outcome of a run, in the units the interface shows. For TCP,
// Mbps is what was carried and Retransmits the cost of getting it there. For
// UDP, Mbps is what was delivered, OfferedMbps what was pushed to get it, and
// LossPercent/JitterMs what the overshoot cost - the numbers a flood exists
// to produce.
type Result struct {
	Protocol    string  `json:"protocol"`
	Mbps        float64 `json:"mbps"`
	OfferedMbps float64 `json:"offered_mbps,omitempty"`
	LossPercent float64 `json:"loss_percent,omitempty"`
	JitterMs    float64 `json:"jitter_ms,omitempty"`
	Retransmits int     `json:"retransmits,omitempty"`
	Seconds     float64 `json:"seconds"`
	Bytes       int64   `json:"bytes"`
}

// iperfReport is the slice of iperf3's -J output that matters. sum_sent is the
// client's transmit side; for UDP sum_received carries the delivered rate and
// the loss and jitter the receiver measured.
type iperfReport struct {
	Error string `json:"error"`
	Start struct {
		TestStart struct {
			Protocol string `json:"protocol"`
		} `json:"test_start"`
	} `json:"start"`
	End struct {
		SumSent struct {
			BitsPerSecond float64 `json:"bits_per_second"`
			Retransmits   int     `json:"retransmits"`
			Seconds       float64 `json:"seconds"`
			Bytes         int64   `json:"bytes"`
		} `json:"sum_sent"`
		SumReceived struct {
			BitsPerSecond float64 `json:"bits_per_second"`
			JitterMs      float64 `json:"jitter_ms"`
			LostPercent   float64 `json:"lost_percent"`
		} `json:"sum_received"`
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
	res := Result{
		Protocol: rep.Start.TestStart.Protocol,
		Seconds:  rep.End.SumSent.Seconds,
		Bytes:    rep.End.SumSent.Bytes,
	}
	if rep.Start.TestStart.Protocol == "UDP" {
		// Delivered is what the receiver got; offered is what we pushed to
		// get it. The gap, and the loss, are the point of a flood.
		res.Mbps = rep.End.SumReceived.BitsPerSecond / 1e6
		res.OfferedMbps = rep.End.SumSent.BitsPerSecond / 1e6
		res.LossPercent = rep.End.SumReceived.LostPercent
		res.JitterMs = rep.End.SumReceived.JitterMs
		return res, nil
	}
	res.Mbps = rep.End.SumSent.BitsPerSecond / 1e6
	res.Retransmits = rep.End.SumSent.Retransmits
	return res, nil
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
