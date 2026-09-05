package state

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A second claim on the same state file is refused, which is the whole
// point: two daemons writing one file produce a snapshot that alternates
// between two unrelated views and reads as flapping links.
func TestSecondWriterIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")

	first, err := TryLock(path)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	defer first.Close()

	if _, err := TryLock(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("second lock: got %v, want ErrLocked", err)
	}
}

// Releasing hands the file to whoever is waiting, so a daemon that lost
// the race picks the state file up on its own when the other one goes
// away. That is what lets this heal without a restart or a trip to the
// vehicle.
func TestLockIsHandedOverOnRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")

	first, err := TryLock(path)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("release: %v", err)
	}

	second, err := TryLock(path)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	second.Close()
}

// The lock guards a sibling file, never the state file itself. Write
// replaces the state file by rename on every pass, so a lock held on that
// inode would guard something with no name left and each writer would
// happily lock its own orphan.
func TestLockDoesNotDisturbTheStateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")

	lock, err := TryLock(path)
	if err != nil {
		t.Fatalf("lock: %v", err)
	}
	defer lock.Close()

	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("locking created or touched the state file itself: %v", err)
	}
	if _, err := os.Stat(path + ".lock"); err != nil {
		t.Fatalf("lock file missing: %v", err)
	}

	// And a real snapshot written underneath it still lands.
	if err := Write(path, Snapshot{Node: "test"}); err != nil {
		t.Fatalf("write under lock: %v", err)
	}
	got, err := Read(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.Node != "test" {
		t.Fatalf("read back node %q, want %q", got.Node, "test")
	}
}
