// Package config holds the daemon's adjustable settings.
//
// Every value has a working default, so a missing or partial file is not
// an error and nothing has to be set for the daemon to run correctly. The
// file exists to let the web interface change a setting on a running
// system, not to make configuration a prerequisite.
//
// Values are clamped rather than trusted. They are edited through a web
// form by a person who may be tired, in a campground, diagnosing
// something else, and a mistyped zero that turned a report interval into
// a busy loop would be a poor way to find that out.
package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// Config is the set of settings that can be changed on a running daemon.
//
// Only the measurement cadences are here so far, because they are the only
// things that currently exist to tune. The path state machine's thresholds
// and hysteresis windows belong here too once there is a state machine to
// apply them.
type Config struct {
	// EchoIntervalMs is how often measurement feedback is sent. It bounds
	// how quickly a change in a path can be noticed, so protocol.md ties
	// it to the 100-200 ms reaction target.
	EchoIntervalMs int `json:"echo_interval_ms"`

	// ProbeIntervalSeconds is how often path MTU is probed. Path MTU
	// changes on tower handover and 5G-to-LTE fallback, so probing has to
	// continue, but it changes rarely enough not to want a fast cadence.
	ProbeIntervalSeconds int `json:"probe_interval_seconds"`

	// StateIntervalMs is how often the state file is rewritten for the
	// web interface.
	StateIntervalMs int `json:"state_interval_ms"`

	// StatsIntervalSeconds is how often measurements are written to the
	// log.
	StatsIntervalSeconds int `json:"stats_interval_seconds"`
}

// bound describes the permitted range of one setting, and is also what the
// web interface renders as the field's limits.
type bound struct {
	Min, Max, Default int
}

// Bounds are the accepted ranges. The lower limits are the point below
// which a setting would do more harm than good rather than merely being
// aggressive.
var Bounds = map[string]bound{
	"echo_interval_ms":       {Min: 20, Max: 5_000, Default: 100},
	"probe_interval_seconds": {Min: 5, Max: 3_600, Default: 15},
	"state_interval_ms":      {Min: 200, Max: 60_000, Default: 1_000},
	"stats_interval_seconds": {Min: 5, Max: 3_600, Default: 30},
}

// Defaults returns a configuration that is correct to run with as-is.
func Defaults() Config {
	return Config{
		EchoIntervalMs:       Bounds["echo_interval_ms"].Default,
		ProbeIntervalSeconds: Bounds["probe_interval_seconds"].Default,
		StateIntervalMs:      Bounds["state_interval_ms"].Default,
		StatsIntervalSeconds: Bounds["stats_interval_seconds"].Default,
	}
}

// clamp brings one value inside its permitted range, substituting the
// default for anything unset.
func clamp(v int, b bound) int {
	switch {
	case v == 0:
		return b.Default
	case v < b.Min:
		return b.Min
	case v > b.Max:
		return b.Max
	}
	return v
}

// Sanitised returns the configuration with every value brought inside its
// permitted range. An out-of-range setting is corrected rather than
// refused, so a bad edit can never leave the daemon unable to start.
func (c Config) Sanitised() Config {
	return Config{
		EchoIntervalMs:       clamp(c.EchoIntervalMs, Bounds["echo_interval_ms"]),
		ProbeIntervalSeconds: clamp(c.ProbeIntervalSeconds, Bounds["probe_interval_seconds"]),
		StateIntervalMs:      clamp(c.StateIntervalMs, Bounds["state_interval_ms"]),
		StatsIntervalSeconds: clamp(c.StatsIntervalSeconds, Bounds["stats_interval_seconds"]),
	}
}

func (c Config) EchoInterval() time.Duration {
	return time.Duration(c.EchoIntervalMs) * time.Millisecond
}

func (c Config) ProbeInterval() time.Duration {
	return time.Duration(c.ProbeIntervalSeconds) * time.Second
}

func (c Config) StateInterval() time.Duration {
	return time.Duration(c.StateIntervalMs) * time.Millisecond
}

func (c Config) StatsInterval() time.Duration {
	return time.Duration(c.StatsIntervalSeconds) * time.Second
}

// Load reads a configuration file. A missing file yields the defaults,
// since running without one is the expected case rather than a problem.
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Defaults(), nil
	}
	if err != nil {
		return Defaults(), err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return Defaults(), fmt.Errorf("config: %s: %w", path, err)
	}
	return c.Sanitised(), nil
}

// Save writes a configuration file, replacing it atomically so a daemon
// reading it concurrently never sees a half-written file.
func Save(path string, c Config) error {
	b, err := json.MarshalIndent(c.Sanitised(), "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".config-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
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

// Holder carries the current configuration for readers on other
// goroutines.
type Holder struct {
	v atomic.Pointer[Config]
}

func NewHolder(c Config) *Holder {
	h := &Holder{}
	h.Set(c)
	return h
}

func (h *Holder) Get() Config {
	if c := h.v.Load(); c != nil {
		return *c
	}
	return Defaults()
}

func (h *Holder) Set(c Config) {
	sane := c.Sanitised()
	h.v.Store(&sane)
}

// Watch reloads the configuration whenever the file changes, so a setting
// altered through the web interface takes effect without a restart.
//
// The file's modification time is polled rather than watched. It changes
// about as often as a person clicks save, and polling avoids a watch that
// has to be re-established every time the file is atomically replaced.
func (h *Holder) Watch(path string) {
	var last time.Time
	for range time.Tick(2 * time.Second) {
		fi, err := os.Stat(path)
		if err != nil {
			continue // a missing file just means the defaults still stand
		}
		if !fi.ModTime().After(last) {
			continue
		}
		last = fi.ModTime()

		c, err := Load(path)
		if err != nil {
			log.Printf("config: reload failed, keeping current settings: %v", err)
			continue
		}
		h.Set(c)
		log.Printf("config: reloaded from %s", path)
	}
}
