package safefile

import (
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// OpenLookupDir pins a directory for relative lookups. The caller closes the descriptor.
func OpenLookupDir(path string) (int, error) {
	return unix.Open(path, parentDirectoryAccess|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
}

// OpenRegularNoFollow opens a regular file for reading after pinning its
// parent directory. Ancestor links are allowed. The final entry must be a regular file.
func OpenRegularNoFollow(path string) (*os.File, error) {
	dir, name := filepath.Split(path)
	parent, err := OpenLookupDir(dir)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)
	return OpenRegularNoFollowAt(parent, name)
}

// OpenRegularNoFollowAt opens one regular file in a pinned directory.
func OpenRegularNoFollowAt(parent int, name string) (*os.File, error) {
	if !filepath.IsLocal(name) || filepath.Base(name) != name || name == "." {
		return nil, fs.ErrInvalid
	}

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
	// The descriptor already identifies the file. The name is only diagnostic.
	f := os.NewFile(uintptr(fd), "regular file")
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
