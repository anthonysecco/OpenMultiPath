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

	// ManagesPaths says whether this end owns its physical sockets. The
	// initiator binds one per WAN link and so can report each as bound or
	// not; the responder only ever learns paths from what arrives, and
	// its per-path bind fields would read as "down" for every healthy
	// path if the interface did not know to leave them out.
	ManagesPaths bool `json:"manages_paths"`

	Paths     []Path        `json:"paths"`
	Aggregate Aggregate     `json:"aggregate"`
	Scheduler Scheduler     `json:"scheduler"`
	Config    config.Config `json:"config"`
}

// Scheduler is what the path selector currently believes.
type Scheduler struct {
	// Primary is the path carrying traffic, or -1 when none has been
	// chosen. SwitchingTo is the path being handed over to during a
	// make-before-break overlap, or -1.
	Primary     int  `json:"primary"`
	Switching   bool `json:"switching"`
	SwitchingTo int  `json:"switching_to"`

	// Blind means no path is in a usable state and traffic is being sent
	// on everything available in the hope that something gets through.
	// It is the fail-to-a-working-state behaviour, and it deserves to be
	// conspicuous: it means the measurements have stopped being able to
	// say anything useful.
	Blind bool `json:"blind"`

	// Reason is the scheduler's own one-line account of the current
	// choice, which is the first thing worth reading when the choice looks
	// wrong.
	Reason        string `json:"reason,omitempty"`
	DuplicateMode string `json:"duplicate_mode,omitempty"`

	// Ranking is every eligible path, best first. architecture.md's
	// fallback needs exactly this written down somewhere a script can read
	// it, because the scheduler is the thing that will have died.
	//
	// Held as int rather than uint8 because encoding/json treats a []uint8
	// as a byte string and base64s it, which turns the one field a
	// recovery script has to read into "AQA=".
	Ranking []int `json:"ranking,omitempty"`
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

	Received uint64 `json:"received"`
	Lost     uint64 `json:"lost"`

	// RecentLossPercent covers roughly the last minute; LossPercent is
	// for all time. The recent figure is the one to lead with, since a
	// lifetime rate goes on reporting an incident that is already over.
	RecentLossPercent float64 `json:"recent_loss_percent"`
	LossPercent       float64 `json:"loss_percent"`

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

	// What the far end reports about our SEND direction on this path
	// (D-024). Everything above is measured locally and therefore describes
	// packets arriving - the other direction from the one a send decision is
	// about. TxReported says whether a report is in hand and recent; when it
	// is false the scheduler is scoring on half a round trip and the inbound
	// figures, and these are meaningless.
	TxReported     bool    `json:"tx_reported"`
	TxSpreadMs     float64 `json:"tx_spread_ms"`
	TxQueueDelayMs float64 `json:"tx_queue_delay_ms"`
	TxJitterMs     float64 `json:"tx_jitter_ms"`
	TxLossPercent  float64 `json:"tx_loss_percent"`

	// TxDelayMs is the one-way delay estimate the scheduler actually ranks
	// on: half the round-trip floor, plus what the peer says it is queueing.
	// The first half is a symmetry assumption and the second is measured;
	// see outboundDelayMs for why that split is the honest one.
	TxDelayMs float64 `json:"tx_delay_ms"`

	// RTTFloorMs is the round trip with nothing queued on it.
	RTTFloorMs float64 `json:"rtt_floor_ms"`

	// The reactive bandwidth ceiling of D-023, all in kbps in the send
	// direction.
	//
	// SendKbps is what is going onto the path right now and PeakKbps the
	// most that ever has. ProvenKbps is the most it has carried without the
	// link underneath starting to queue - a floor on its capacity, not a
	// ceiling. CeilingKbps is where queueing was actually observed to set
	// in, and CeilingKnown distinguishes that from never having seen it.
	// LimitKbps is what the scheduler is currently willing to assume, which
	// is the ceiling discounted for how long ago it was confirmed; zero
	// there means no opinion, and no gate.
	//
	// CeilingAgeSeconds is what ages. The estimate itself does not decay:
	// an hour of idleness is not evidence that a link shrank, so the number
	// stands and only the confidence in it slides. -1 means nothing has
	// ever loaded the path.
	SendKbps          float64 `json:"send_kbps"`
	PeakKbps          float64 `json:"peak_kbps"`
	ProvenKbps        float64 `json:"proven_kbps"`
	CeilingKbps       float64 `json:"ceiling_kbps"`
	CeilingKnown      bool    `json:"ceiling_known"`
	LimitKbps         float64 `json:"limit_kbps"`
	CeilingAgeSeconds float64 `json:"ceiling_age_seconds"`

	// State is stable, unstable or down, and StateReason says what put it
	// there. The reason matters as much as the state: "unstable (jitter)"
	// and "unstable (below the tunnel floor)" call for entirely different
	// responses from whoever is reading this at the roadside.
	State       string `json:"state,omitempty"`
	StateReason string `json:"state_reason,omitempty"`

	// RFactor is the raw E-model quality score for the path and Score is
	// that figure after the scheduler's penalties. The two differing is
	// the visible evidence of a penalty being applied - a path with a
	// healthy R and a poor Score is being held back for flapping, not for
	// its measurements.
	RFactor float64 `json:"r_factor"`
	Score   float64 `json:"score"`

	// MOS is Score expressed on the 1-to-5 scale, for reading at a glance.
	MOS float64 `json:"mos"`

	// Flapping means this path has changed state too often to be trusted,
	// and Transitions is how many times within the flap window.
	Flapping    bool `json:"flapping,omitempty"`
	Transitions int  `json:"transitions"`

	// Sending means traffic is currently going out of this path, and
	// Primary that it is the chosen one. They differ during a handover and
	// while duplicating.
	Sending bool `json:"sending"`
	Primary bool `json:"primary,omitempty"`

	LastSeenSeconds float64 `json:"last_seen_seconds"`
	Alive           bool    `json:"alive"`

	// Bound is whether this end currently holds an open socket on the
	// link, and Local the address it is bound to. Only meaningful when
	// the snapshot's ManagesPaths is set.
	//
	// Bound and Alive answer different questions and both are needed: a
	// path bound but not alive means the link is up here and something
	// past it is broken, while a path neither bound nor alive means the
	// modem has not come back yet.
	Bound bool   `json:"bound,omitempty"`
	Local string `json:"local,omitempty"`

	// Drops counts how many times this link has gone away since the
	// daemon started, address changes included. A link that has dropped
	// forty times on one drive is the most useful single thing the field
	// data can say about it, and it is what the flap penalty will be
	// built on.
	Drops uint64 `json:"drops,omitempty"`
}

// Burst is one bucket of the loss run-length distribution.
type Burst struct {
	Label string `json:"label"`
	Count uint64 `json:"count"`
}

// Aggregate is the whole tunnel at a glance.
type Aggregate struct {
	Received uint64 `json:"received"`
	Lost     uint64 `json:"lost"`

	// RecentLossPercent covers roughly the last minute; LossPercent is
	// for all time. The recent figure is the one to lead with, since a
	// lifetime rate goes on reporting an incident that is already over.
	RecentLossPercent float64 `json:"recent_loss_percent"`
	LossPercent       float64 `json:"loss_percent"`
	PathsTotal        int     `json:"paths_total"`
	PathsAlive        int     `json:"paths_alive"`

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
