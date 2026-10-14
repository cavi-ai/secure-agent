// Package durablefs supplies directory synchronization for local durable files.
package durablefs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// MakeDir creates missing directories and syncs their entries from the leaf
// back through the first existing ancestor. Existing permissions are preserved.
func MakeDir(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	var missing []string
	ancestor := path
	for {
		info, err := os.Stat(ancestor)
		if err == nil {
			if !info.IsDir() {
				return errors.New("durable file parent is not a directory")
			}
			break
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		missing = append(missing, ancestor)
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return err
		}
		ancestor = parent
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	for _, dir := range missing {
		if err := SyncDir(dir); err != nil {
			return err
		}
	}
	if len(missing) > 0 {
		return SyncDir(ancestor)
	}
	return nil
}

func SyncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}
