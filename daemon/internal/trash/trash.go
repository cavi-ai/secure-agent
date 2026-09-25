// Package trash moves a directory to the Trash on its own volume, the way
// Finder does on macOS and the freedesktop Trash elsewhere, so a cleanup is
// undone by putting the item back.
package trash

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/diskusage"
)

// Mover moves paths into the Trash of the user whose home is Home.
type Mover struct {
	Home string
	GOOS string
	Now  func() time.Time
}

// Move renames path into the Trash on its own volume: ~/.Trash for the
// home volume, <volume>/.Trashes/<uid> for others (what Finder uses). A
// name already in the Trash gets a time suffix, as Finder does. It returns
// where the item went.
func (m Mover) Move(path string) (string, error) {
	dir, err := m.dir(path)
	if err != nil {
		return "", err
	}
	dest := filepath.Join(dir, filepath.Base(path))
	if _, err := os.Lstat(dest); err == nil {
		dest = filepath.Join(dir, filepath.Base(path)+" "+m.Now().Format("15.04.05.000"))
	}
	if err := os.Rename(path, dest); err != nil {
		return "", fmt.Errorf("move to Trash: %w", err)
	}
	if m.GOOS != "darwin" {
		// freedesktop Trash: a .trashinfo beside files/ lets the desktop
		// show the item's origin and restore it.
		info := filepath.Join(filepath.Dir(dir), "info", filepath.Base(dest)+".trashinfo")
		body := "[Trash Info]\nPath=" + (&url.URL{Path: path}).EscapedPath() + "\nDeletionDate=" + m.Now().Format("2006-01-02T15:04:05") + "\n"
		if err := os.MkdirAll(filepath.Dir(info), 0o700); err == nil {
			_ = os.WriteFile(info, []byte(body), 0o600)
		}
	}
	return dest, nil
}

func (m Mover) dir(path string) (string, error) {
	if m.GOOS != "darwin" {
		dir := filepath.Join(m.Home, ".local", "share", "Trash", "files")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		if !diskusage.SameDevice(dir, path) {
			return "", errors.New("the Trash is on another volume")
		}
		return dir, nil
	}
	home := filepath.Join(m.Home, ".Trash")
	if diskusage.SameDevice(m.Home, path) {
		return home, os.MkdirAll(home, 0o700)
	}
	dir := filepath.Join(diskusage.Root(path), ".Trashes", strconv.Itoa(os.Getuid()))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("volume Trash: %w", err)
	}
	return dir, nil
}
