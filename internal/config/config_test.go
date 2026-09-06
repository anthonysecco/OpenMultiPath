package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// Nothing has to be configured for the daemon to run correctly, so a
// missing file is the expected case rather than an error.
func TestMissingFileYieldsDefaults(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("Load of a missing file returned %v, want no error", err)
	}
	if !reflect.DeepEqual(c, Defaults()) {
		t.Errorf("got %+v, want the defaults %+v", c, Defaults())
	}
}

// These are typed into a web form by someone who may be tired and
// diagnosing something else. A zero that turned a report cadence into a
// busy loop would be a poor way to discover that.
func TestValuesAreClampedIntoRange(t *testing.T) {
	wild := Defaults()
	wild.EchoIntervalMs = 0
	wild.ProbeIntervalSeconds = -5
	wild.StateIntervalMs = 10_000_000
	wild.StatsIntervalSeconds = 1
	got := wild.Sanitised()

	// A zero on a setting whose floor is above zero is out of range like
	// any other out-of-range value, and is pulled up to the floor. It is
	// no longer read as "unset": see TestExplicitZeroIsKeptWhereZeroIsValid
	// for why that distinction had to be made.
	if want := Bounds["echo_interval_ms"].Min; got.EchoIntervalMs != want {
		t.Errorf("echo interval = %d from a zero, want the minimum %d", got.EchoIntervalMs, want)
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
	c := Defaults()
	c.EchoIntervalMs = 250
	c.ProbeIntervalSeconds = 60
	c.StateIntervalMs = 2_000
	c.StatsIntervalSeconds = 45
	c.RecordIntervalSeconds = 10
	c.RecordMaxMegabytes = 64
	c.RecordKeepFiles = 4

	if got := c.Sanitised(); !reflect.DeepEqual(got, c) {
		t.Errorf("got %+v, want it unchanged at %+v", got, c)
	}
}

// Several scoring settings have a legitimate zero: it is how a penalty is
// switched off. Reading that as "unset, use the default" would silently
// restore the penalty someone had just disabled, and they would have no way
// to tell from the form that it had not taken.
func TestExplicitZeroIsKeptWhereZeroIsValid(t *testing.T) {
	c := Defaults()
	c.FlapPenaltyR = 0
	c.SwitchMarginR = 0
	c.BaseDelayMs = 0

	got := c.Sanitised()
	if got.FlapPenaltyR != 0 {
		t.Errorf("flap penalty = %d, want the 0 that switches it off", got.FlapPenaltyR)
	}
	if got.SwitchMarginR != 0 {
		t.Errorf("switch margin = %d, want 0", got.SwitchMarginR)
	}
	if got.BaseDelayMs != 0 {
		t.Errorf("base delay = %d, want 0", got.BaseDelayMs)
	}
}

// An unrecognised duplication policy is a typo, and a typo should not stop
// the daemon starting.
func TestUnknownDuplicateModeFallsBackToTheDefault(t *testing.T) {
	c := Defaults()
	c.DuplicateMode = "sometimes"
	if got := c.Sanitised().DuplicateMode; got != DuplicateSwitching {
		t.Errorf("duplicate mode = %q, want %q", got, DuplicateSwitching)
	}
	for _, mode := range DuplicateModes {
		c.DuplicateMode = mode
		if got := c.Sanitised().DuplicateMode; got != mode {
			t.Errorf("duplicate mode %q was changed to %q", mode, got)
		}
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	want := Defaults()
	want.EchoIntervalMs = 150
	want.ProbeIntervalSeconds = 30
	want.StateIntervalMs = 500
	want.StatsIntervalSeconds = 60
	want.RecordIntervalSeconds = 2
	want.RecordMaxMegabytes = 16
	want.RecordKeepFiles = 12
	want.DuplicateMode = DuplicateUnstable
	want.FlapPenaltyR = 0

	if err := Save(path, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
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
	if !reflect.DeepEqual(c, Defaults()) {
		t.Errorf("got %+v, want the defaults so the daemon can still run", c)
	}
}

// A file written before a setting existed is the normal case after any
// upgrade: the boxes in the field are carrying one right now. The settings
// it does name must survive, and the ones it does not must come up at
// their defaults rather than at zero.
func TestPartialFileKeepsWhatItNamesAndDefaultsTheRest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"echo_interval_ms": 200}`), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.EchoIntervalMs != 200 {
		t.Errorf("echo interval = %d, want the 200 the file asked for", got.EchoIntervalMs)
	}
	if want := Bounds["record_interval_seconds"].Default; got.RecordIntervalSeconds != want {
		t.Errorf("record interval = %d, want the default %d", got.RecordIntervalSeconds, want)
	}
	if want := Bounds["record_keep_files"].Default; got.RecordKeepFiles != want {
		t.Errorf("record keep files = %d, want the default %d", got.RecordKeepFiles, want)
	}
	if got.RecordMaxBytes() <= 0 {
		t.Error("rotation threshold is not positive, so the recorder would rotate on every write")
	}
}

// A cap nobody set has to mean "no opinion", not "no allowance". Reading
// it the other way would have a fresh install refuse to carry bulk on
// every link it has.
func TestUnconfiguredLinkIsUnmetered(t *testing.T) {
	c := Defaults()
	l := c.LinkFor("enp1s0")
	if l.CapMB != 0 {
		t.Errorf("unconfigured link has cap %d MB, want 0 meaning unmetered", l.CapMB)
	}
	if l.CycleDay < 1 || l.CycleDay > 28 {
		t.Errorf("unconfigured link cycle day is %d, want a usable default", l.CycleDay)
	}
}

// There is no zeroth of the month, so a zero cycle day can only mean the
// field was omitted - the one place in this file a zero is filled in
// rather than taken literally.
func TestOmittedCycleDayGetsTheDefault(t *testing.T) {
	c := Defaults()
	c.Links = map[string]LinkBudget{"enp1s0": {CapMB: 102400}}
	c = c.Sanitised()

	if got := c.Links["enp1s0"].CycleDay; got != Bounds["link_cycle_day"].Default {
		t.Errorf("cycle day sanitised to %d, want the default %d", got, Bounds["link_cycle_day"].Default)
	}
	if got := c.LinkFor("enp1s0").CapMB; got != 102400 {
		t.Errorf("cap came back as %d MB, want 102400", got)
	}
}

func TestLinkBudgetsAreClamped(t *testing.T) {
	c := Defaults()
	c.Links = map[string]LinkBudget{
		"low":  {CapMB: -5, CycleDay: 0},
		"high": {CapMB: 51200, CycleDay: 31},
	}
	c = c.Sanitised()

	if got := c.Links["low"].CapMB; got != 0 {
		t.Errorf("negative cap sanitised to %d, want 0", got)
	}
	if got := c.Links["high"].CycleDay; got != 28 {
		t.Errorf("cycle day 31 sanitised to %d, want 28; there is no 31st in February", got)
	}
}

// Sanitised runs on configuration other goroutines are already reading
// through the holder. Correcting the map in place would be a data race
// that only appears under load on the box hardest to reach.
func TestSanitisedDoesNotMutateTheCallersLinkMap(t *testing.T) {
	c := Defaults()
	c.Links = map[string]LinkBudget{"enp1s0": {CapMB: 102400, CycleDay: 31}}
	original := c.Links["enp1s0"]

	_ = c.Sanitised()

	if c.Links["enp1s0"] != original {
		t.Errorf("Sanitised edited the caller's map: %+v, want %+v", c.Links["enp1s0"], original)
	}
}

// The watcher must react to any change, not merely to a newer timestamp.
// Two things on a vehicle produce a config file that is different but not
// newer: a restore from a `cp -a` backup, which preserves the older
// mtime, and a write that happened before NTP stepped the clock backwards
// on a box with no RTC. Testing for "newer" leaves the daemon running
// settings nobody can see, with nothing in the log to say so.
func TestWatchReloadsAConfigWithAnOlderTimestamp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	first := Defaults()
	first.EchoIntervalMs = 250
	if err := Save(path, first); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Start from the defaults, not from `first`, so there is an
	// observable transition proving the watcher has read the file and
	// recorded its timestamp. Without that the first tick can land after
	// the whole setup and the test passes without exercising anything.
	h := NewHolder(Defaults())
	go h.Watch(path)
	waitFor(t, h, 250, "the watcher never made its first read")

	// Now a restore that puts back different content with an older
	// mtime, exactly as `cp -a` from yesterday's backup would.
	second := Defaults()
	second.EchoIntervalMs = 400
	if err := Save(path, second); err != nil {
		t.Fatalf("Save: %v", err)
	}
	old := time.Now().Add(-24 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	waitFor(t, h, 400, "the watcher ignored a changed config with an older mtime")
}

func waitFor(t *testing.T, h *Holder, want int, msg string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if h.Get().EchoIntervalMs == want {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s: echo interval is %d ms, want %d", msg, h.Get().EchoIntervalMs, want)
}
