// Package linkspeed is the vehicle's record of each link's measured speed
// (D-055).
//
// The flow test (internal/diag, D-053) measures a link's raw speed in both
// directions when a person presses "Measure Link Speed". ompui saves the
// result here, keyed by the link's interface name, and the vehicle's ompd
// watches the file: it shapes its own sends on that link to ShapePercent of
// the upload figure, and passes the whole set to home over the wire so home
// can shape its sends to ShapePercent of the download figure.
//
// A link with no entry, or zero in a direction, has never been measured and
// is treated as unlimited. That is the working default: an unmeasured link is
// not a small one, and shaping it to a guess would throttle a good link on no
// evidence.
//
// The last measurement stands until the link is measured again or the entry
// is cleared. Nothing ages it and nothing infers from traffic. A future
// enhancement is expected to detect a link's speed dynamically from real
// traffic and loss, supplementing this measured figure rather than replacing
// it; see D-055.
//
// ompui is the only writer (D-032's rule), and every write replaces the file
// atomically, so ompd never reads half of one.
package linkspeed

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// DefaultPath is where the vehicle keeps its measurements. /var/lib rather
// than /etc: these are measured results, not settings anyone chose, and the
// configuration file is served to the web interface wholesale.
const DefaultPath = "/var/lib/openmultipath/linkspeed.json"

// ShapePercent is how much of a measured speed ompd lets itself send, counted
// in full wire bytes including every header and tunnel overhead. The margin
// keeps the daemon's own queue - where the call can be put first - ahead of
// the carrier's, where it cannot.
//
// A constant, not a setting: the owner set 95%, and every tunable needs a
// working default the user never has to touch.
const ShapePercent = 95

// ShapedKbps is the most ompd sends on a link measured at kbps, or 0 -
// unlimited - for a link never measured.
func ShapedKbps(kbps float64) float64 {
	if kbps <= 0 {
		return 0
	}
	return kbps * ShapePercent / 100
}

// Measurement is one link's last measured speed. Up is vehicle to home, down
// is home to vehicle, both the physical-link rate at the IP layer in kbps.
// Zero in a direction means that direction has never been measured.
type Measurement struct {
	UpKbps       float64 `json:"up_kbps"`
	DownKbps     float64 `json:"down_kbps"`
	MeasuredUnix int64   `json:"measured_unix"`
}

// File is the whole record, keyed by interface name - the same name ompd's
// -paths flag uses - so a measurement follows its link even if the list is
// reordered and path ids move.
type File struct {
	Links map[string]Measurement `json:"links"`
}

// Load reads the record. A missing file is an empty record and no error:
// nothing measured yet is the normal state of a fresh install.
func Load(path string) (File, error) {
	f := File{Links: map[string]Measurement{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return File{Links: map[string]Measurement{}}, fmt.Errorf("linkspeed: %s: %w", path, err)
	}
	if f.Links == nil {
		f.Links = map[string]Measurement{}
	}
	for name, m := range f.Links {
		if m.UpKbps < 0 {
			m.UpKbps = 0
		}
		if m.DownKbps < 0 {
			m.DownKbps = 0
		}
		f.Links[name] = m
	}
	return f, nil
}

// Save replaces the record atomically.
func Save(path string, f File) error {
	if f.Links == nil {
		f.Links = map[string]Measurement{}
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".linkspeed-*.json")
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
