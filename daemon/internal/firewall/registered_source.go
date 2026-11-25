package firewall

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// ValidateRegisteredSource checks the same boundary used on every ingest.
func ValidateRegisteredSource(path string) error {
	f, err := openRegisteredSource(path)
	if err != nil {
		return err
	}
	return f.Close()
}

func openRegisteredSource(path string) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("path must be absolute or ~-relative")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	// macOS volumes can be case-insensitive, including for directory aliases.
	folded := strings.ToLower(resolved)
	for _, dir := range []string{
		"/etc", "/private/etc", "/system", "/library",
		"/usr", "/bin", "/sbin", "/var/db", "/private/var/db",
	} {
		if folded == dir || strings.HasPrefix(folded, dir+"/") {
			return nil, fmt.Errorf("refusing to ingest a system path: %s", resolved)
		}
	}
	if resolved == "/" {
		return nil, fmt.Errorf("must be a regular file")
	}

	// Walk the checked path without following links introduced after resolution.
	// Each directory descriptor pins the parent used by the next lookup.
	const dirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	dir, err := unix.Open("/", dirFlags, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(resolved, "/"), "/")
	for _, part := range parts[:len(parts)-1] {
		next, err := unix.Openat(dir, part, dirFlags, 0)
		_ = unix.Close(dir)
		if err != nil {
			return nil, err
		}
		dir = next
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), resolved)
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("must be a regular file")
	}
	return f, nil
}
