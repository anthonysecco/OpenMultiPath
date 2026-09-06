package diag

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
)

// SpeedResult is one public-internet speed test over a path's physical link.
// Rates are Mbit/s, delays milliseconds, bytes the data the test actually
// spent - which on a metered link is the cost, so it is carried through and
// shown rather than discarded.
type SpeedResult struct {
	DownloadMbps  float64 `json:"download_mbps"`
	UploadMbps    float64 `json:"upload_mbps"`
	PingMs        float64 `json:"ping_ms"`
	JitterMs      float64 `json:"jitter_ms"`
	Server        string  `json:"server"`
	BytesSent     int64   `json:"bytes_sent"`
	BytesReceived int64   `json:"bytes_received"`
}

// librespeedReport is the slice of librespeed-cli's --json that matters. The
// tool prints a one-element array, one entry per server it tested.
type librespeedReport struct {
	Server struct {
		Name string `json:"name"`
	} `json:"server"`
	Ping          float64 `json:"ping"`
	Jitter        float64 `json:"jitter"`
	Upload        float64 `json:"upload"`
	Download      float64 `json:"download"`
	BytesSent     int64   `json:"bytes_sent"`
	BytesReceived int64   `json:"bytes_received"`
}

// ParseSpeedtest turns librespeed-cli --json output into a SpeedResult.
func ParseSpeedtest(out []byte) (SpeedResult, error) {
	var reps []librespeedReport
	if err := json.Unmarshal(out, &reps); err != nil {
		return SpeedResult{}, fmt.Errorf("speedtest output was not JSON (is librespeed-cli installed?): %w", err)
	}
	if len(reps) == 0 {
		return SpeedResult{}, fmt.Errorf("speedtest produced no result (no reachable server?)")
	}
	r := reps[0]
	return SpeedResult{
		DownloadMbps:  r.Download,
		UploadMbps:    r.Upload,
		PingMs:        r.Ping,
		JitterMs:      r.Jitter,
		Server:        r.Server.Name,
		BytesSent:     r.BytesSent,
		BytesReceived: r.BytesReceived,
	}, nil
}

// RunSpeedtest runs the omp-speedtest helper for one path and parses the
// result. The helper resolves the wg transport to the physical NIC beneath it
// and pins the test there; see deploy/omp-speedtest. helperPath lets the
// caller name the binary; empty uses "omp-speedtest" from PATH.
func RunSpeedtest(ctx context.Context, helperPath, iface string, seconds int) (SpeedResult, error) {
	if helperPath == "" {
		helperPath = "omp-speedtest"
	}
	out, runErr := exec.CommandContext(ctx, helperPath, iface, strconv.Itoa(seconds)).Output()

	res, parseErr := ParseSpeedtest(out)
	if parseErr == nil {
		return res, nil
	}
	if runErr != nil {
		if ctx.Err() != nil {
			return SpeedResult{}, fmt.Errorf("speedtest did not finish in time: %w", ctx.Err())
		}
		// The helper writes its own diagnostics to stderr; surface them.
		if ee, ok := runErr.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			return SpeedResult{}, fmt.Errorf("speedtest: %s", ee.Stderr)
		}
		return SpeedResult{}, fmt.Errorf("speedtest failed to run: %w", runErr)
	}
	return SpeedResult{}, parseErr
}
