package store

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestFlagMirrorsHaveIndependentRotationLimits(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	small, err := openFlagMirror(filepath.Join(dir, "small.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer small.close()
	small.rotateBytes = 1
	standard, err := openFlagMirror(filepath.Join(dir, "standard.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer standard.close()
	for _, mirror := range []*flagMirror{small, standard} {
		for _, id := range []string{"first", "second", "third"} {
			if err := mirror.append(model.Flag{ID: id}); err != nil {
				t.Fatal(err)
			}
		}
	}
	assertMirrorIDs(t, small.path, "third")
	assertMirrorIDs(t, small.path+".1", "second")
	assertMirrorIDs(t, standard.path, "first", "second", "third")
	if _, err := os.Stat(standard.path + ".1"); !os.IsNotExist(err) {
		t.Fatalf("another mirror's limit caused rotation: %v", err)
	}
	for _, path := range []string{small.path, small.path + ".1", standard.path} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("mirror permissions = %o, want 600", info.Mode().Perm())
		}
	}
}

func assertMirrorIDs(t *testing.T, path string, want ...string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	for _, id := range want {
		var flag model.Flag
		if err := decoder.Decode(&flag); err != nil {
			t.Fatal(err)
		}
		if flag.ID != id {
			t.Fatalf("mirror flag = %q, want %q", flag.ID, id)
		}
	}
	var extra model.Flag
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("unexpected extra mirror record: %+v, error: %v", extra, err)
	}
}
