package trash

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func trashFixture(t *testing.T) (Mover, string, string) {
	t.Helper()
	home := t.TempDir()
	source := filepath.Join(home, "work tree")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "keep.txt"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(home, ".local", "share", "Trash")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	m := Mover{Home: home, GOOS: "linux", Now: func() time.Time {
		return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	}}
	return m, source, root
}

func TestMovePreservesSourceWhenTrashInfoUnavailable(t *testing.T) {
	m, source, root := trashFixture(t)
	if err := os.WriteFile(filepath.Join(root, "info"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if dest, err := m.Move(source); err == nil || dest != "" {
		t.Fatalf("unavailable restore metadata: destination=%q err=%v", dest, err)
	}
	if data, err := os.ReadFile(filepath.Join(source, "keep.txt")); err != nil || string(data) != "keep" {
		t.Fatalf("source changed: data=%q err=%v", data, err)
	}
}

func TestMoveDoesNotOverwriteTrashInfo(t *testing.T) {
	m, source, root := trashFixture(t)
	infoDir := filepath.Join(root, "info")
	if err := os.Mkdir(infoDir, 0o700); err != nil {
		t.Fatal(err)
	}
	info := filepath.Join(infoDir, "work tree.trashinfo")
	if err := os.WriteFile(info, []byte("prior restore metadata"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Move(source); err == nil {
		t.Fatal("accepted conflicting restore metadata")
	}
	if data, err := os.ReadFile(info); err != nil || string(data) != "prior restore metadata" {
		t.Fatalf("prior restore metadata changed: data=%q err=%v", data, err)
	}
	if _, err := os.Stat(filepath.Join(source, "keep.txt")); err != nil {
		t.Fatalf("source changed: %v", err)
	}
}

func TestMoveWritesTrashRestoreMetadata(t *testing.T) {
	m, source, root := trashFixture(t)
	dest, err := m.Move(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(source); !os.IsNotExist(err) {
		t.Fatalf("source still present: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(dest, "keep.txt")); err != nil || string(data) != "keep" {
		t.Fatalf("trashed contents changed: data=%q err=%v", data, err)
	}
	info := filepath.Join(root, "info", "work tree.trashinfo")
	data, err := os.ReadFile(info)
	if err != nil {
		t.Fatal(err)
	}
	want := "[Trash Info]\nPath=" + strings.ReplaceAll(source, " ", "%20") + "\nDeletionDate=2026-01-02T03:04:05\n"
	if string(data) != want {
		t.Fatalf("restore metadata=%q want=%q", data, want)
	}
	st, err := os.Stat(info)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("restore metadata is not private: stat=%v err=%v", st, err)
	}
}

func TestMoveRemovesPreparedTrashInfoWhenRenameFails(t *testing.T) {
	m, source, root := trashFixture(t)
	for _, name := range []string{"work tree", "work tree 03.04.05.000"} {
		dir := filepath.Join(root, "files", name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "existing.txt"), []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.Move(source); err == nil {
		t.Fatal("rename over nonempty directory succeeded")
	}
	if _, err := os.Stat(filepath.Join(source, "keep.txt")); err != nil {
		t.Fatalf("source changed: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "info"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("prepared metadata was not removed: entries=%v err=%v", entries, err)
	}
}
