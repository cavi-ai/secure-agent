package firewall

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSaltCreatesAndPersists(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "fw-salt")

	s1, err := LoadSalt(p)
	if err != nil || len(s1) < 16 {
		t.Fatalf("first LoadSalt: err=%v len=%d", err, len(s1))
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("salt file not created: %v", err)
	}
	s2, err := LoadSalt(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(s1) != string(s2) {
		t.Fatal("salt must be stable across loads")
	}
}
