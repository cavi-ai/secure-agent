package firewall

import (
	"path/filepath"
	"testing"
)

func TestModeStorePersistsAcrossLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "firewall-modes.json")
	s := NewModeStore(path)

	if len(s.Load()) != 0 {
		t.Fatal("fresh store should be empty")
	}
	if err := s.Set("aws-key", "block"); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("openai-key", "monitor"); err != nil {
		t.Fatal(err)
	}

	// A new store reading the same file must see the persisted overrides.
	got := NewModeStore(path).Load()
	if got["aws-key"] != "block" {
		t.Fatalf("aws-key = %q, want block", got["aws-key"])
	}
	if got["openai-key"] != "monitor" {
		t.Fatalf("openai-key = %q, want monitor", got["openai-key"])
	}
}
