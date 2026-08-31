// Package state carries the daemon's measurements to the web interface.
//
// The interface reads a file rather than asking the daemon, which is
// deliberate. The moment the interface matters most is the moment the
// daemon has stopped answering, and a file still holds the last thing that
// was true along with the timestamp that says how long ago that was.
// Stale-but-visible data is what diagnosis needs; a connection refused is
// not.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
)

// Snapshot is everything the interface renders.
type Snapshot struct {
	Node    string `json:"node"`
	Role    string `json:"role"`
	Version string `json:"version"`

	// UpdatedUnix is when this snapshot was taken, in seconds. The
	// interface shows its age prominently, because every other number
	// here is only as true as this one is recent.
	UpdatedUnix   float64 `json:"updated_unix"`
	UptimeSeconds float64 `json:"uptime_seconds"`

	// TunnelMTU is what the interface is actually set to;
	// RecommendedTunnelMTU is what the paths were measured to support. The
	// two differing is worth seeing, since applying the recommendation is
	// still a manual step.
	TunnelMTU            int `json:"tunnel_mtu"`
	RecommendedTunnelMTU int `json:"recommended_tunnel_mtu"`

	Paths     []Path        `json:"paths"`
	Aggregate Aggregate     `json:"aggregate"`
	Config    config.Config `json:"config"`
}

// Path is one link's measurements.
type Path struct {
	ID     uint8  `json:"id"`
	Name   string `json:"name,omitempty"`
	Remote string `json:"remote,omitempty"`

	RTTMs        float64 `json:"rtt_ms"`
	P95SpreadMs  float64 `json:"p95_spread_ms"`
	JitterMs     float64 `json:"jitter_ms"`
	QueueDelayMs float64 `json:"queue_delay_ms"`

	Received    uint64  `json:"received"`
	Lost        uint64  `json:"lost"`
	LossPercent float64 `json:"loss_percent"`

	// Bursts is the distribution of consecutive-loss run lengths. A rate
	// alone cannot distinguish scattered loss, which concealment handles,
	// from a burst, which is audible.
	Bursts []Burst `json:"bursts"`

	// Samples and Thin say how much to trust the rest. protocol.md is
	// explicit that ten packets tells you nothing about a loss rate.
	Samples int  `json:"samples"`
	Thin    bool `json:"thin"`

	PathMTU int  `json:"path_mtu"`
	Usable  bool `json:"usable"`

	LastSeenSeconds float64 `json:"last_seen_seconds"`
	Alive           bool    `json:"alive"`
}

// Burst is one bucket of the loss run-length distribution.
type Burst struct {
	Label string `json:"label"`
	Count uint64 `json:"count"`
}

// Aggregate is the whole tunnel at a glance.
type Aggregate struct {
	Received    uint64  `json:"received"`
	Lost        uint64  `json:"lost"`
	LossPercent float64 `json:"loss_percent"`
	PathsTotal  int     `json:"paths_total"`
	PathsAlive  int     `json:"paths_alive"`

	// BestRTTMs is the lowest round trip currently measured across live
	// paths, which is the best the tunnel could do if it were steering
	// perfectly.
	BestRTTMs float64 `json:"best_rtt_ms"`
}

// Write replaces the state file atomically, so the interface reading it
// concurrently never sees a partial write.
func Write(path string, s Snapshot) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Read loads the last snapshot the daemon wrote.
func Read(path string) (Snapshot, error) {
	var s Snapshot
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("state: %s: %w", path, err)
	}
	return s, nil
}

// Age is how long ago the snapshot was taken. The interface leads with
// this: a large age means the daemon has stopped writing, and every other
// figure on the page is history rather than fact.
func (s Snapshot) Age() time.Duration {
	if s.UpdatedUnix == 0 {
		return 0
	}
	sec, frac := int64(s.UpdatedUnix), s.UpdatedUnix-float64(int64(s.UpdatedUnix))
	return time.Since(time.Unix(sec, int64(frac*1e9)))
}
