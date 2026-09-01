package record

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixed is the limits function for a test that does not change them.
func fixed(maxBytes int64, keep int) func() (int64, int) {
	return func() (int64, int) { return maxBytes, keep }
}

type sample struct {
	N int    `json:"n"`
	S string `json:"s"`
}

func lines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return out
}

func TestWritesOneJSONObjectPerLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.jsonl")
	w := New(path, fixed(1<<20, 4))
	defer w.Close()

	for i := 0; i < 3; i++ {
		if err := w.Write(sample{N: i, S: "canyon"}); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	got := lines(t, path)
	if len(got) != 3 {
		t.Fatalf("got %d lines, want 3", len(got))
	}
	for i, l := range got {
		var s sample
		if err := json.Unmarshal([]byte(l), &s); err != nil {
			t.Fatalf("line %d is not valid JSON: %v", i, err)
		}
		if s.N != i {
			t.Fatalf("line %d holds n=%d", i, s.N)
		}
	}
}

// The daemon is restarted for every field upgrade. History from before the
// restart has to survive it.
func TestAppendsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.jsonl")

	first := New(path, fixed(1<<20, 4))
	if err := first.Write(sample{N: 1}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	second := New(path, fixed(1<<20, 4))
	defer second.Close()
	if err := second.Write(sample{N: 2}); err != nil {
		t.Fatalf("write: %v", err)
	}

	if got := lines(t, path); len(got) != 2 {
		t.Fatalf("got %d lines after reopen, want 2", len(got))
	}
}

func TestRotatesAndBoundsDiskUse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")

	// Room for roughly two records per file, so a short run rotates
	// several times and pushes past the keep limit.
	const keep = 3
	w := New(path, fixed(80, keep))
	defer w.Close()

	for i := 0; i < 40; i++ {
		if err := w.Write(sample{N: i, S: strings.Repeat("x", 20)}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != keep+1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("got %d files (%v), want %d: the current log plus %d generations",
			len(entries), names, keep+1, keep)
	}

	// The ceiling is what protects the disk the daemon, the state file and
	// the journal all share, so it must hold rather than merely roughly hold.
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			t.Fatalf("stat %s: %v", e.Name(), err)
		}
		if fi.Size() > 80 {
			t.Errorf("%s is %d bytes, over the 80 byte rotation threshold", e.Name(), fi.Size())
		}
	}

	// The newest records are the ones that must survive.
	last := lines(t, path)
	if len(last) == 0 {
		t.Fatal("current log is empty")
	}
	var s sample
	if err := json.Unmarshal([]byte(last[len(last)-1]), &s); err != nil {
		t.Fatalf("last line invalid: %v", err)
	}
	if s.N != 39 {
		t.Fatalf("last record is n=%d, want the most recent (39)", s.N)
	}
}

// A record larger than the whole rotation budget must still be written
// rather than silently dropped or looping forever.
func TestOversizedRecordStillWritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.jsonl")
	w := New(path, fixed(32, 2))
	defer w.Close()

	if err := w.Write(sample{N: 1, S: strings.Repeat("y", 500)}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := lines(t, path); len(got) != 1 {
		t.Fatalf("got %d lines, want 1", len(got))
	}
}

// Every other setting takes effect on a running daemon, and this one has
// to as well: a tunable that silently needs a restart is a trap for
// someone who has already changed it and is waiting for it to matter.
func TestLoweredKeepLimitFreesTheDiskItPromised(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")

	keep := 6
	w := New(path, func() (int64, int) { return 80, keep })
	defer w.Close()

	for i := 0; i < 40; i++ {
		if err := w.Write(sample{N: i, S: strings.Repeat("x", 20)}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != keep+1 {
		t.Fatalf("got %d files, want %d before the limit is lowered", len(entries), keep+1)
	}

	// Someone on a nearly full disk turns it down.
	keep = 2
	for i := 40; i < 60; i++ {
		if err := w.Write(sample{N: i, S: strings.Repeat("x", 20)}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != keep+1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("got %d files (%v), want %d: generations above the new limit were stranded",
			len(entries), names, keep+1)
	}
}
