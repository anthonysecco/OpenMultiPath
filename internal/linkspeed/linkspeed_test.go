package linkspeed

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMissingFileIsAnEmptyRecord(t *testing.T) {
	f, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if f.Links == nil || len(f.Links) != 0 {
		t.Errorf("links = %v, want an empty map", f.Links)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "linkspeed.json")
	in := File{Links: map[string]Measurement{
		"wg1": {UpKbps: 12_000, DownKbps: 95_000, MeasuredUnix: 1_790_000_000},
	}}
	if err := Save(path, in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if out.Links["wg1"] != in.Links["wg1"] {
		t.Errorf("round trip = %+v, want %+v", out.Links["wg1"], in.Links["wg1"])
	}
}

// A corrupt file must not shape anything: an empty record is unlimited on
// every link, which is the working state.
func TestCorruptFileLoadsEmptyWithAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "linkspeed.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err == nil {
		t.Error("corrupt file loaded without an error")
	}
	if len(f.Links) != 0 {
		t.Errorf("corrupt file yielded links %v", f.Links)
	}
}

func TestShapedKbps(t *testing.T) {
	if got := ShapedKbps(10_000); got != 9_500 {
		t.Errorf("ShapedKbps(10000) = %v, want 9500", got)
	}
	if got := ShapedKbps(0); got != 0 {
		t.Errorf("unmeasured shaped to %v, want 0 (unlimited)", got)
	}
}
