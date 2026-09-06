// Package safefile provides crash-consistent writes for the daemon's
// security-state files. A bare os.WriteFile can leave a truncated file if the
// daemon is killed mid-write (it is designed to survive SIGKILL), and the
// corresponding Load paths then treat the file as corrupt and drop ALL state —
// block promotions, fingerprints, sources. Temp-file + fsync + rename means a
// crash leaves the old file or the new file, never a torn one.
package safefile

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFileAtomic writes data to path atomically with the given permissions:
// a temp file in the same directory (so rename stays on one filesystem),
// fsync, then rename over the target. The perm is applied to the temp file
// before rename, so it takes effect even when replacing an existing file with
// different permissions (unlike os.WriteFile, which preserves the old mode).
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("safefile: mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("safefile: create temp for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("safefile: chmod temp for %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("safefile: write temp for %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("safefile: fsync temp for %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("safefile: close temp for %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("safefile: rename onto %s: %w", path, err)
	}
	return nil
}
