package safefile

import (
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// OpenRegularNoFollow opens a regular file for reading after pinning its
// parent directory. Ancestor links are allowed; the final entry must be a
// regular file. os.Root.OpenFile may resolve links within its root.
func OpenRegularNoFollow(path string) (*os.File, error) {
	dir, name := filepath.Split(path)
	parent, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)

	// Check the entry before opening it to avoid opening known devices.
	var entry unix.Stat_t
	if err := unix.Fstatat(parent, name, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	if entry.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fs.ErrInvalid
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, fs.ErrInvalid
	}
	return f, nil
}
