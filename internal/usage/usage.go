// Package usage accounts for how much each link has carried in its
// current billing cycle, and turns that into the budget band the
// scheduler penalises on.
//
// It reads the kernel's own per-interface byte counters rather than
// running vnstat, which architecture.md originally named. Three reasons.
// The counters are already there, so there is no second daemon to install
// and keep running on a box nobody visits for months. They count
// everything on the wire including WireGuard's overhead, which is what the
// carrier bills and what the daemon's own tunnel counters would undercount.
// And a cycle date configured here stays in one place: vnstat keeps its own
// per-interface config, which would make the billing day a second policy
// surface that could disagree with this one.
//
// What it must survive is spelled out in scope-v1.md: "Losing these on
// every power cycle means relearning at exactly the moment the RV is
// likely moving." So totals are accumulated from deltas and written to
// disk, and a counter that goes backwards - a reboot, a modem replug, an
// interface bounced by the link watcher - is read as a reset rather than
// as negative traffic.
package usage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Band is how much of a link's allowance is left, in the three states
// architecture.md defines. The zero value is Green, which is what an
// unconfigured link has to be: a cap nobody set is not a cap of zero.
type Band int

const (
	// Green is normal running: duplicate freely, bulk goes anywhere.
	Green Band = iota

	// Yellow is on course to exceed the cap. Real-time is still allowed,
	// duplication onto this link stops, and bulk goes elsewhere if
	// anywhere else will take it.
	Yellow

	// Red is the allowance actually spent. Real-time only, and only
	// because a working call beats an overage; nothing else rides this
	// link.
	Red
)

func (b Band) String() string {
	switch b {
	case Yellow:
		return "yellow"
	case Red:
		return "red"
	default:
		return "green"
	}
}

// Budget is one link's allowance. A zero Cap means unmetered, which is
// the default for every link nobody has configured - and it has to mean
// "no opinion" rather than "no allowance", or the first thing an
// unconfigured box would do is refuse to carry bulk.
type Budget struct {
	// CapBytes is the billing-cycle allowance. Zero means unmetered.
	CapBytes uint64

	// CycleDay is the day of the month the carrier's cycle starts.
	// Restricted to 1-28 by the config bounds, because a cycle starting on
	// the 31st does not exist in February and the carriers that do this
	// bill on a date that always exists.
	CycleDay int

	// GreenHeadroomPercent is how much of the cap must still be projected
	// spare to count as green. architecture.md sets it at 20.
	GreenHeadroomPercent int
}

// State is what is known about one link right now.
type State struct {
	Band Band

	// Bytes is what has gone over the link this cycle, both directions.
	// Carriers bill both, and a download counts against the cap whichever
	// way the packets were headed.
	Bytes uint64

	// Projected is the whole-cycle figure the current burn rate implies,
	// and Metered says whether any of this is meaningful - an unmetered
	// link still reports Bytes, which is worth seeing, but has no cap to
	// project against.
	Projected uint64
	Metered   bool

	CycleStart time.Time
}

// link is one interface's persisted accounting.
type link struct {
	Bytes      uint64    `json:"bytes"`
	CycleStart time.Time `json:"cycle_start"`

	// LastRaw is the kernel counter as of the last sample. Deltas are
	// taken against it, and a smaller value means the counter reset
	// underneath us rather than that traffic went backwards.
	LastRaw uint64 `json:"last_raw"`
	HaveRaw bool   `json:"have_raw"`
}

// Meter accumulates per-link usage and survives restarts.
type Meter struct {
	mu    sync.Mutex
	path  string
	links map[string]*link

	// read returns the total bytes the kernel has counted on an
	// interface. Injectable because the real one reads /sys, and the
	// behaviour worth testing here - a counter resetting mid-cycle, a
	// cycle rolling over - cannot be produced by waiting for it.
	read func(iface string) (uint64, error)

	// dirty tracks whether anything has changed since the last write, so
	// an idle box is not rewriting the same file every sample.
	dirty bool
}

// NewMeter builds a meter persisting to path.
func NewMeter(path string) *Meter {
	return &Meter{path: path, links: map[string]*link{}, read: readSysCounters}
}

// readSysCounters totals the kernel's byte counters for one interface.
//
// Both directions, because carriers bill both. A missing interface is not
// an error worth propagating loudly: a link that has not come up yet is
// the normal case on a cold boot, and scope-v1.md is explicit that modems
// take 30+ seconds to register.
func readSysCounters(iface string) (uint64, error) {
	// Reject anything that could climb out of /sys. Interface names come
	// from the daemon's own -paths flag rather than from the network, so
	// this is belt and braces, but a path traversal into a file that
	// happens to parse as a number would be a silent wrong answer.
	if iface == "" || strings.ContainsAny(iface, "/.") {
		return 0, fmt.Errorf("usage: invalid interface name %q", iface)
	}
	var total uint64
	for _, dir := range []string{"rx_bytes", "tx_bytes"} {
		b, err := os.ReadFile(filepath.Join("/sys/class/net", iface, "statistics", dir))
		if err != nil {
			return 0, err
		}
		n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("usage: %s %s: %w", iface, dir, err)
		}
		total += n
	}
	return total, nil
}

// Load reads the persisted totals. A missing file is the normal first run
// and is not an error: starting from zero loses a cycle's accounting,
// which is worse than nothing but far better than refusing to start.
func (m *Meter) Load() error {
	b, err := os.ReadFile(m.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var f struct {
		Links map[string]*link `json:"links"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return fmt.Errorf("usage: %s: %w", m.path, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if f.Links != nil {
		m.links = f.Links
	}
	return nil
}

// Save writes the totals, and is a no-op when nothing has changed.
func (m *Meter) Save() error {
	m.mu.Lock()
	if !m.dirty {
		m.mu.Unlock()
		return nil
	}
	b, err := json.Marshal(struct {
		Links map[string]*link `json:"links"`
	}{m.links})
	m.dirty = false
	m.mu.Unlock()
	if err != nil {
		return err
	}

	dir := filepath.Dir(m.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".usage-*.json")
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
	return os.Rename(tmp.Name(), m.path)
}

// Sample folds the current kernel counters for one interface into its
// cycle total.
//
// An interface that cannot be read is skipped silently and its LastRaw
// left alone, so a link that disappears and comes back resumes counting
// from where it stopped rather than treating its whole lifetime total as
// new traffic.
func (m *Meter) Sample(iface string, b Budget, now time.Time) {
	raw, err := m.read(iface)
	if err != nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	l := m.links[iface]
	if l == nil {
		l = &link{CycleStart: CycleStart(b.CycleDay, now)}
		m.links[iface] = l
		m.dirty = true
	}

	// Roll the cycle before adding, so traffic that arrives after the
	// billing date lands in the new cycle rather than topping up the old
	// one's final reading.
	if start := CycleStart(b.CycleDay, now); start.After(l.CycleStart) {
		l.Bytes = 0
		l.CycleStart = start
		m.dirty = true
	}

	switch {
	case !l.HaveRaw:
		// First reading of this run. The counter already holds whatever
		// the interface carried before the daemon started, and none of
		// that is ours to attribute - it is either already counted in the
		// persisted total or predates it. Take the reading as a baseline
		// and count forward from here.
		l.HaveRaw = true
	case raw < l.LastRaw:
		// The counter went backwards, so it reset: a reboot, a replugged
		// modem, an interface the link watcher bounced. Everything
		// currently showing is new since that reset.
		l.Bytes += raw
		m.dirty = true
	default:
		if d := raw - l.LastRaw; d > 0 {
			l.Bytes += d
			m.dirty = true
		}
	}
	l.LastRaw = raw
}

// State reports what is known about one link.
func (m *Meter) State(iface string, b Budget, now time.Time) State {
	m.mu.Lock()
	l := m.links[iface]
	var used uint64
	start := CycleStart(b.CycleDay, now)
	if l != nil {
		used = l.Bytes
		if !l.CycleStart.IsZero() && !start.After(l.CycleStart) {
			start = l.CycleStart
		}
	}
	m.mu.Unlock()

	s := State{Bytes: used, CycleStart: start, Metered: b.CapBytes > 0}
	if !s.Metered {
		return s
	}
	s.Projected = Projected(used, start, now)
	s.Band = BandOf(used, s.Projected, start, now, b)
	return s
}

// CycleStart is the most recent occurrence of the billing day, at
// midnight local time.
//
// Local rather than UTC because a carrier's billing day is a date on a
// bill, and a vehicle that crosses a time zone should not get a second
// cycle boundary or skip one.
func CycleStart(day int, now time.Time) time.Time {
	if day < 1 {
		day = 1
	}
	if day > 28 {
		day = 28
	}
	y, mo, d := now.Date()
	start := time.Date(y, mo, day, 0, 0, 0, 0, now.Location())
	if d < day {
		start = start.AddDate(0, -1, 0)
	}
	return start
}

// cycleEnd is the next billing day after start.
func cycleEnd(start time.Time) time.Time { return start.AddDate(0, 1, 0) }

// Projected is the whole-cycle total the burn rate so far implies.
//
// Returns the raw usage rather than a projection during the first day of
// a cycle. Dividing by a few hours of elapsed time turns one overnight
// backup into a projection of several hundred gigabytes, which would
// red-line a link on the first morning of every month and then quietly
// correct itself - the kind of confident wrong answer that costs more
// trust than having no answer at all.
func Projected(used uint64, start, now time.Time) uint64 {
	elapsed := now.Sub(start)
	if elapsed < 24*time.Hour {
		return used
	}
	total := cycleEnd(start).Sub(start)
	if total <= 0 {
		return used
	}
	return uint64(float64(used) * (float64(total) / float64(elapsed)))
}

// BandOf places a link in its budget band.
//
// architecture.md defines green as more than 20% projected headroom and
// yellow as projected to exceed, which leaves the span between them
// unnamed. Yellow takes it. A link on course to land inside its cap with
// only a sliver spare is not comfortable, and the cost of calling it
// yellow is that duplication stops and bulk prefers another link - both
// recoverable, both cheap, and both exactly what somebody watching a cap
// would want.
func BandOf(used, projected uint64, start, now time.Time, b Budget) Band {
	if b.CapBytes == 0 {
		return Green
	}
	if used >= b.CapBytes {
		return Red
	}
	headroom := b.GreenHeadroomPercent
	if headroom < 0 {
		headroom = 0
	}
	greenCeiling := uint64(float64(b.CapBytes) * float64(100-headroom) / 100)
	if projected <= greenCeiling {
		return Green
	}
	return Yellow
}
