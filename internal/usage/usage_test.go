package usage

import (
	"io/fs"
	"path/filepath"
	"testing"
	"time"
)

const gb = 1 << 30

func testBudget(capGB uint64) Budget {
	return Budget{CapBytes: capGB * gb, CycleDay: 1, GreenHeadroomPercent: 20}
}

// meterOn builds a meter whose counter is driven by the returned pointer,
// so a test can move the kernel's numbers around directly.
func meterOn(t *testing.T, raw *uint64) *Meter {
	t.Helper()
	m := NewMeter(filepath.Join(t.TempDir(), "usage.json"))
	m.read = func(string) (uint64, error) { return *raw, nil }
	return m
}

func at(day int, hour int) time.Time {
	return time.Date(2026, time.September, day, hour, 0, 0, 0, time.Local)
}

// The first reading of a run is a baseline, not traffic. The counter
// already holds whatever the link carried before the daemon started, and
// counting that as new would charge the whole cycle again on every
// restart.
func TestFirstSampleIsABaseline(t *testing.T) {
	raw := uint64(500 * gb)
	m := meterOn(t, &raw)

	m.Sample("wan0", testBudget(100), at(10, 0))
	if got := m.State("wan0", testBudget(100), at(10, 0)).Bytes; got != 0 {
		t.Fatalf("first sample counted %d bytes, want 0", got)
	}

	raw += 3 * gb
	m.Sample("wan0", testBudget(100), at(10, 1))
	if got := m.State("wan0", testBudget(100), at(10, 1)).Bytes; got != 3*gb {
		t.Errorf("counted %d bytes after 3 GB of traffic, want %d", got, 3*gb)
	}
}

// A reboot, a replugged modem or an interface the link watcher bounced
// all reset the kernel counter. Everything showing after that is new.
func TestCounterResetIsNotNegativeTraffic(t *testing.T) {
	raw := uint64(10 * gb)
	m := meterOn(t, &raw)
	m.Sample("wan0", testBudget(100), at(10, 0))

	raw = 14 * gb
	m.Sample("wan0", testBudget(100), at(10, 1))
	if got := m.State("wan0", testBudget(100), at(10, 1)).Bytes; got != 4*gb {
		t.Fatalf("counted %d, want %d before the reset", got, 4*gb)
	}

	// The interface bounces: counter restarts from zero, then carries 2 GB.
	raw = 2 * gb
	m.Sample("wan0", testBudget(100), at(10, 2))

	if got := m.State("wan0", testBudget(100), at(10, 2)).Bytes; got != 6*gb {
		t.Errorf("counted %d after a counter reset, want %d", got, 6*gb)
	}
}

// scope-v1.md: losing these on a power cycle means relearning at exactly
// the moment the RV is likely moving.
func TestTotalsSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "usage.json")

	raw := uint64(0)
	first := NewMeter(path)
	first.read = func(string) (uint64, error) { return raw, nil }
	first.Sample("wan0", testBudget(100), at(10, 0))
	raw = 7 * gb
	first.Sample("wan0", testBudget(100), at(10, 1))
	if err := first.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	// A new process, with the kernel counter still where it was.
	second := NewMeter(path)
	second.read = func(string) (uint64, error) { return raw, nil }
	if err := second.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := second.State("wan0", testBudget(100), at(10, 2)).Bytes; got != 7*gb {
		t.Fatalf("after restart counted %d, want %d", got, 7*gb)
	}

	// And the reboot's own counter reset does not double-count.
	raw = 1 * gb
	second.Sample("wan0", testBudget(100), at(10, 3))
	if got := second.State("wan0", testBudget(100), at(10, 3)).Bytes; got != 8*gb {
		t.Errorf("after a restart plus counter reset counted %d, want %d", got, 8*gb)
	}
}

func TestCycleRollsOverOnTheBillingDay(t *testing.T) {
	raw := uint64(0)
	m := meterOn(t, &raw)
	b := testBudget(100)

	m.Sample("wan0", b, at(20, 0))
	raw = 60 * gb
	m.Sample("wan0", b, at(25, 0))
	if got := m.State("wan0", b, at(25, 0)).Bytes; got != 60*gb {
		t.Fatalf("mid-cycle counted %d, want %d", got, 60*gb)
	}

	// Past the billing day into the next month.
	raw += 2 * gb
	m.Sample("wan0", b, time.Date(2026, time.October, 2, 0, 0, 0, 0, time.Local))

	s := m.State("wan0", b, time.Date(2026, time.October, 2, 0, 0, 0, 0, time.Local))
	if s.Bytes != 2*gb {
		t.Errorf("after the billing day counted %d, want only the %d since it", s.Bytes, 2*gb)
	}
	if s.CycleStart.Month() != time.October {
		t.Errorf("cycle start is %s, want October", s.CycleStart)
	}
}

// A cap nobody set is not a cap of zero. An unconfigured link has to come
// out green, or a fresh install refuses to carry bulk.
func TestUnconfiguredLinkIsGreen(t *testing.T) {
	raw := uint64(0)
	m := meterOn(t, &raw)
	b := Budget{CycleDay: 1, GreenHeadroomPercent: 20}

	m.Sample("wan0", b, at(10, 0))
	raw = 900 * gb
	m.Sample("wan0", b, at(20, 0))

	s := m.State("wan0", b, at(20, 0))
	if s.Band != Green {
		t.Errorf("unmetered link with 900 GB on it is %s, want green", s.Band)
	}
	if s.Metered {
		t.Error("unmetered link reported as metered")
	}
	if s.Bytes != 900*gb {
		t.Errorf("unmetered link counted %d bytes, want them still tracked", s.Bytes)
	}
}

// One overnight backup on the first morning of a cycle would otherwise
// project to several hundred gigabytes and red-line the link, then
// quietly correct itself over the following days.
func TestNoProjectionInsideTheFirstDay(t *testing.T) {
	b := testBudget(100)
	start := CycleStart(1, at(1, 6))

	// 5 GB in the first six hours projects to 600 GB if divided out.
	if got := Projected(5*gb, start, at(1, 6)); got != 5*gb {
		t.Errorf("projected %d inside the first day, want the raw %d", got, 5*gb)
	}
	if band := BandOf(5*gb, Projected(5*gb, start, at(1, 6)), start, at(1, 6), b); band != Green {
		t.Errorf("band is %s on the first morning, want green", band)
	}

	// By day ten the same rate is a real signal: 50 GB in 10 days of a
	// 30 day cycle projects to 150 GB against a 100 GB cap.
	if band := BandOf(50*gb, Projected(50*gb, start, at(11, 0)), start, at(11, 0), b); band != Yellow {
		t.Errorf("band is %s at 50 GB by day ten of a 100 GB cap, want yellow", band)
	}
}

func TestBands(t *testing.T) {
	b := testBudget(100)
	start := CycleStart(1, at(1, 0))
	now := at(16, 0) // halfway through a 30 day cycle

	cases := []struct {
		name string
		used uint64
		want Band
	}{
		// 30 GB by the halfway point projects to 60 GB, comfortably under
		// the 80 GB green ceiling.
		{"burning slowly", 30 * gb, Green},
		// 45 GB projects to 90 GB: inside the cap, but past the 20%
		// headroom architecture.md wants.
		{"on course to just scrape in", 45 * gb, Yellow},
		// 60 GB projects to 120 GB, over the cap outright.
		{"on course to exceed", 60 * gb, Yellow},
		// Spent is spent, whatever the projection says.
		{"cap spent", 100 * gb, Red},
		{"over the cap", 140 * gb, Red},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := BandOf(tc.used, Projected(tc.used, start, now), start, now, b)
			if got != tc.want {
				t.Errorf("%d GB used is %s, want %s", tc.used/gb, got, tc.want)
			}
		})
	}
}

// The billing day is a date on a bill. A link read before the day has
// arrived this month belongs to the cycle that started last month.
func TestCycleStartWalksBackBeforeTheBillingDay(t *testing.T) {
	got := CycleStart(15, at(3, 12))
	want := time.Date(2026, time.August, 15, 0, 0, 0, 0, time.Local)
	if !got.Equal(want) {
		t.Errorf("cycle start is %s, want %s", got, want)
	}

	if got := CycleStart(15, at(20, 12)); got.Month() != time.September || got.Day() != 15 {
		t.Errorf("cycle start is %s, want 15 September", got)
	}
}

// An interface that is not up yet is the normal case on a cold boot, not
// a fault, and it must not disturb the total already counted.
func TestUnreadableInterfaceIsSkipped(t *testing.T) {
	raw := uint64(0)
	m := meterOn(t, &raw)
	m.Sample("wan0", testBudget(100), at(10, 0))
	raw = 5 * gb
	m.Sample("wan0", testBudget(100), at(10, 1))

	m.read = func(string) (uint64, error) { return 0, fs.ErrNotExist }
	m.Sample("wan0", testBudget(100), at(10, 2))

	if got := m.State("wan0", testBudget(100), at(10, 2)).Bytes; got != 5*gb {
		t.Errorf("counted %d after the interface vanished, want the %d already counted", got, 5*gb)
	}

	// And when it comes back, counting resumes from where it stopped
	// rather than charging the interface's whole lifetime again.
	m.read = func(string) (uint64, error) { return raw, nil }
	raw = 6 * gb
	m.Sample("wan0", testBudget(100), at(10, 3))
	if got := m.State("wan0", testBudget(100), at(10, 3)).Bytes; got != 6*gb {
		t.Errorf("counted %d after the interface returned, want %d", got, 6*gb)
	}
}
