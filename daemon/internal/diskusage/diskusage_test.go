package diskusage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func write(t *testing.T, p string, n int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, make([]byte, n), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDirCountsAllocatedBytesNewestAndSkips(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "a.bin"), 10000)
	write(t, filepath.Join(root, "sub", "b.bin"), 5000)
	write(t, filepath.Join(root, "nested", "big.bin"), 50000)
	if err := os.Symlink("/", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-72 * time.Hour)
	newer := time.Now().Add(-time.Hour)
	for _, p := range []string{"a.bin", "sub/b.bin", "nested/big.bin", "sub", "nested", "."} {
		_ = os.Chtimes(filepath.Join(root, p), old, old)
	}
	_ = os.Chtimes(filepath.Join(root, "sub", "b.bin"), newer, newer)
	tv := unix.NsecToTimeval(old.UnixNano())
	if err := unix.Lutimes(filepath.Join(root, "link"), []unix.Timeval{tv, tv}); err != nil {
		t.Fatal(err)
	}

	all := Dir(context.Background(), root, nil)
	if all.Partial || all.Bytes < 65000 || all.Files != 4 || all.Newest.Sub(newer).Abs() > time.Second {
		t.Fatalf("Dir = %+v, want >= 65000 bytes, 4 files, newest %v", all, newer)
	}
	skipped := Dir(context.Background(), root, map[string]bool{filepath.Join(root, "nested"): true})
	if skipped.Bytes >= all.Bytes || skipped.Bytes < 15000 {
		t.Fatalf("with nested skipped = %d (all %d)", skipped.Bytes, all.Bytes)
	}
	if u := DirLimit(context.Background(), root, nil, 2); !u.Partial {
		t.Fatal("a walk past MaxEntries must report partial")
	}
}

func TestVolumesOneRowPerVolume(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	v := Volumes([]string{a, b, "/nonexistent/x"})
	if len(v) != 1 || v[0].TotalBytes == 0 || v[0].FreeBytes == 0 || v[0].FreeBytes > v[0].TotalBytes || v[0].Mount == "" {
		t.Fatalf("volumes = %+v", v)
	}
	if !SameDevice(a, b) {
		t.Fatal("two temp dirs must share a device")
	}
}

func TestVolumesDistinguishFilesystemsWithMatchingSpace(t *testing.T) {
	root := t.TempDir()
	a, b := filepath.Join(root, "volume-a"), filepath.Join(root, "volume-b")
	paths := []string{a, b, a, filepath.Join(root, "unavailable")}
	got := volumes(paths, func(path string, st *unix.Statfs_t) error {
		switch path {
		case a:
			st.Fsid.Val = [2]int32{1, 0}
		case b:
			st.Fsid.Val = [2]int32{2, 0}
		default:
			return os.ErrNotExist
		}
		st.Bsize, st.Blocks, st.Bavail = 1, 8000, 500
		return nil
	})
	if len(got) != 2 {
		t.Fatalf("distinct filesystem identities were merged: %+v", got)
	}
	if got[0].Mount != a || got[1].Mount != b || got[0].TotalBytes != 8000 || got[1].FreeBytes != 500 {
		t.Fatalf("volume measurements changed: %+v", got)
	}
}
