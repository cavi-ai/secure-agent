package safefile

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRegularNoFollowInSearchOnlyDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read directories regardless of mode")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := os.WriteFile(path, []byte("contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o100); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Error(err)
		}
	})
	f, err := OpenRegularNoFollow(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if data, err := io.ReadAll(f); err != nil || string(data) != "contents" {
		t.Fatalf("ReadAll = %q, %v", data, err)
	}
}

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
