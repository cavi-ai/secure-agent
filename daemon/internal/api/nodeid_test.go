package api

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadNodeIDPersistsAndStable(t *testing.T) {
	p := filepath.Join(t.TempDir(), "node-id")
	a := LoadNodeID(p)
	if len(a) != 32 {
		t.Fatalf("node id %q not 32 hex chars", a)
	}
	b := LoadNodeID(p)
	if a != b {
		t.Fatalf("node id not stable: %q vs %q", a, b)
	}
}

func TestLoadNodeIDCorruptFileRegenerates(t *testing.T) {
	p := filepath.Join(t.TempDir(), "node-id")
	if a := LoadNodeID(p); len(a) != 32 {
		t.Fatal("expected fresh id")
	}
	// Truncated file must regenerate, not return garbage.
	if err := os.WriteFile(p, []byte("zz"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b := LoadNodeID(p); len(b) != 32 {
		t.Fatalf("corrupt file not regenerated: %q", b)
	}
}
