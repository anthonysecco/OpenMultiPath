package state

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// ErrLocked reports that another live process already holds the state
// file. It is worth distinguishing from every other failure here: a busy
// lock means a second daemon, which is an operator mistake with an exact
// remedy, while the rest are disk problems with no remedy at all.
var ErrLocked = errors.New("state file is held by another process")

// Lock is an exclusive claim on one state file, held for as long as the
// process that took it lives.
//
// Two daemons writing one state file is not a theoretical problem. Each
// rewrites the whole snapshot on its own timer, so the file ends up
// alternating between two unrelated views of the world, and the web
// interface faithfully renders both. From a campground that looks like
// every link flapping between stable and down every few seconds - which
// is indistinguishable from the fault the interface exists to diagnose.
// It happened: a test binary left running after a rollback kept writing
// its dead view of torn-down interfaces for a day, and nothing anywhere
// in the daemon could have told you. The links were perfect throughout.
//
// The lock is advisory and taken with flock, which is what makes it safe
// on a vehicle: the kernel drops it when the holder exits, crashes, or is
// killed outright. There is no stale lock to clear by hand and nothing a
// power cut can leave behind that stops the next boot.
type Lock struct{ f *os.File }

// TryLock claims the right to write path. It never blocks - another
// daemon holding the lock is a condition to report, not to wait out here.
//
// The lock lives in a sibling file rather than in the state file itself,
// because Write replaces the state file by rename on every pass. A lock
// taken on that inode would guard a file that no longer has a name, and
// each writer would contentedly lock its own orphan.
//
// The lock file is never removed. Unlinking it would let a second process
// create a fresh inode and lock that instead, which is precisely the
// collision this exists to prevent. An empty file costs nothing.
func TryLock(path string) (*Lock, error) {
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("state: open lock for %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("state: lock %s: %w", f.Name(), err)
	}
	return &Lock{f: f}, nil
}

// Close releases the lock. Closing the descriptor is what releases it, so
// the kernel does the same at exit; this exists for tests and for the
// rare orderly shutdown.
func (l *Lock) Close() error { return l.f.Close() }
