//go:build linux

package collect

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestOpenRolloutFilesReadsProcFD(t *testing.T) {
	root := t.TempDir()
	fd := filepath.Join(root, "100", "fd")
	if err := os.MkdirAll(fd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(rolloutA, filepath.Join(fd, "7")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(fd, "0")); err != nil {
		t.Fatal(err)
	}
	prev := procRoot
	procRoot = root
	defer func() { procRoot = prev }()
	got, err := OpenRolloutFiles([]int32{100, 200})
	if err != nil || !reflect.DeepEqual(got, map[int32][]string{100: {rolloutA}}) {
		t.Fatalf("OpenRolloutFiles = %v, %v; want pid 100 → rolloutA", got, err)
	}
}
