// Package record appends telemetry snapshots to a rotating log on disk.
//
// The state file the web interface reads holds exactly one moment: it is
// overwritten every second, so a canyon transit leaves nothing behind to
// look at afterwards. scope-v1.md puts field data collection ahead of
// every scheduling decision in the project - thresholds are meant to come
// from a week of real link behaviour rather than from reasoning - and that
// requires the drive to produce a file.
//
// The format is one JSON object per line. It appends without rewriting,
// survives an unclean shutdown with at most a partial final line, and can
// be read by anything. A structured store would buy queries the analysis
// does not yet know it needs, at the cost of a component that can fail on
// a box 800 miles away.
package record

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Writer appends snapshots to a file, rotating it by size and keeping a
// bounded number of older generations.
//
// The bound matters more than it looks: this runs on an RV box that may go
// months between anyone looking at it, and an unbounded history log fills
// the disk that the daemon, the state file and the system journal all
// share. Losing the oldest hour of history is recoverable; losing the
// ability to write anything is not.
type Writer struct {
	path string

	// limits is read on every write rather than captured once, so the
	// ceiling can be changed on a running daemon like every other
	// setting. A tunable that silently needs a restart is a trap for
	// someone who has already changed it and is waiting for it to matter.
	limits func() (maxBytes int64, keep int)

	mu   sync.Mutex
	f    *os.File
	size int64
}

// New prepares a writer. The file is opened lazily on the first write, so
// constructing one costs nothing and a disk that is not ready yet is not
// an error at startup.
func New(path string, limits func() (maxBytes int64, keep int)) *Writer {
	return &Writer{path: path, limits: limits}
}

// bounds reads the current limits, holding them to values that make sense
// whatever the caller supplies.
func (w *Writer) bounds() (int64, int) {
	maxBytes, keep := w.limits()
	if maxBytes < 1 {
		maxBytes = 1
	}
	if keep < 1 {
		keep = 1
	}
	return maxBytes, keep
}

// Write appends one record as a single line.
func (w *Writer) Write(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.openLocked(); err != nil {
		return err
	}
	maxBytes, keep := w.bounds()
	// Rotate before writing rather than after, so the size ceiling is
	// never exceeded even by a single oversized record.
	if w.size > 0 && w.size+int64(len(b)) > maxBytes {
		if err := w.rotateLocked(keep); err != nil {
			return err
		}
	}
	n, err := w.f.Write(b)
	w.size += int64(n)
	return err
}

// Close releases the current file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.closeLocked()
}

func (w *Writer) closeLocked() error {
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f, w.size = nil, 0
	return err
}

// openLocked opens the current file for appending, picking up the size of
// whatever is already there so a restart does not reset the rotation
// budget.
func (w *Writer) openLocked() error {
	if w.f != nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(w.path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.f, w.size = f, fi.Size()
	return nil
}

// rotateLocked shifts the generations along: the current file becomes .1,
// .1 becomes .2, and whatever was at the end is discarded.
func (w *Writer) rotateLocked(keep int) error {
	if err := w.closeLocked(); err != nil {
		return err
	}
	// Remove the oldest first, then walk backwards so no rename ever
	// overwrites a generation that has not been moved yet.
	//
	// Everything from the limit upwards goes, not just the one generation
	// that has fallen off the end. Lowering the setting has to actually
	// free the disk it promised to free; generations left stranded above
	// a reduced limit would never be collected by anything.
	for i := keep; ; i++ {
		err := os.Remove(w.gen(i))
		if os.IsNotExist(err) {
			break // generations are contiguous, so this is the end
		}
		if err != nil {
			return err
		}
	}
	for i := keep - 1; i >= 1; i-- {
		if err := os.Rename(w.gen(i), w.gen(i+1)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.Rename(w.path, w.gen(1)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return w.openLocked()
}

// gen names the nth older generation of the log.
func (w *Writer) gen(n int) string { return fmt.Sprintf("%s.%d", w.path, n) }
