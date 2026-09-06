package safefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomicCreatesWithPerms(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state", "guard-modes.json")
	if err := WriteFileAtomic(p, []byte(`{"a":"b"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"a":"b"}` {
		t.Fatalf("content = %q", data)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("perms = %v, want 0600", fi.Mode().Perm())
	}
	// No temp files left behind.
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Fatalf("leftover temp files: %v", entries)
	}
}

func TestWriteFileAtomicReplacesAndFixesPerms(t *testing.T) {
	// The key property os.WriteFile lacks: replacing an existing file must
	// apply the new mode, not preserve the old one.
	p := filepath.Join(t.TempDir(), "ca.key")
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(p, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("perms after replace = %v, want 0600", fi.Mode().Perm())
	}
	data, _ := os.ReadFile(p)
	if string(data) != "new" {
		t.Fatalf("content = %q", data)
	}
}
