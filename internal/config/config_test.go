package config

import (
	"os"
	"path/filepath"
	"testing"
)

// Nothing has to be configured for the daemon to run correctly, so a
// missing file is the expected case rather than an error.
func TestMissingFileYieldsDefaults(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("Load of a missing file returned %v, want no error", err)
	}
	if c != Defaults() {
		t.Errorf("got %+v, want the defaults %+v", c, Defaults())
	}
}

// These are typed into a web form by someone who may be tired and
// diagnosing something else. A zero that turned a report cadence into a
// busy loop would be a poor way to discover that.
func TestValuesAreClampedIntoRange(t *testing.T) {
	wild := Config{
		EchoIntervalMs:       0,
		ProbeIntervalSeconds: -5,
		StateIntervalMs:      10_000_000,
		StatsIntervalSeconds: 1,
	}
	got := wild.Sanitised()

	if want := Bounds["echo_interval_ms"].Default; got.EchoIntervalMs != want {
		t.Errorf("echo interval = %d from a zero, want the default %d", got.EchoIntervalMs, want)
	}
	if want := Bounds["probe_interval_seconds"].Min; got.ProbeIntervalSeconds != want {
		t.Errorf("probe interval = %d from a negative, want the minimum %d", got.ProbeIntervalSeconds, want)
	}
	if want := Bounds["state_interval_ms"].Max; got.StateIntervalMs != want {
		t.Errorf("state interval = %d from an absurd value, want the maximum %d", got.StateIntervalMs, want)
	}
	if want := Bounds["stats_interval_seconds"].Min; got.StatsIntervalSeconds != want {
		t.Errorf("stats interval = %d from below the floor, want %d", got.StatsIntervalSeconds, want)
	}

	if got.EchoInterval() <= 0 {
		t.Error("echo interval is not a positive duration after sanitising")
	}
}

// A value inside its range is left exactly as given.
func TestValidValuesSurviveUntouched(t *testing.T) {
	c := Config{
		EchoIntervalMs:       250,
		ProbeIntervalSeconds: 60,
		StateIntervalMs:      2_000,
		StatsIntervalSeconds: 45,
	}
	if got := c.Sanitised(); got != c {
		t.Errorf("got %+v, want it unchanged at %+v", got, c)
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	want := Config{
		EchoIntervalMs:       150,
		ProbeIntervalSeconds: 30,
		StateIntervalMs:      500,
		StatsIntervalSeconds: 60,
	}
	if err := Save(path, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

// A file damaged by anything other than this program must not take the
// daemon down with it.
func TestCorruptFileFallsBackToDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("{ this is not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	c, err := Load(path)
	if err == nil {
		t.Error("Load of a corrupt file returned no error; the damage should be reported")
	}
	if c != Defaults() {
		t.Errorf("got %+v, want the defaults so the daemon can still run", c)
	}
}
