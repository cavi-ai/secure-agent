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
	var info string
	if m.GOOS != "darwin" {
		info, err = m.prepareInfo(path, dest)
		if err != nil {
			return "", fmt.Errorf("prepare Trash restore metadata: %w", err)
		}
	}
	if err := os.Rename(path, dest); err != nil {
		if info != "" {
			err = errors.Join(err, os.Remove(info))
		}
		return "", fmt.Errorf("move to Trash: %w", err)
	}
	return dest, nil
}

// prepareInfo persists the origin before moving the directory. An existing
// record belongs to another item and must never be overwritten.
func (m Mover) prepareInfo(path, dest string) (string, error) {
	info := filepath.Join(filepath.Dir(filepath.Dir(dest)), "info", filepath.Base(dest)+".trashinfo")
	if err := os.MkdirAll(filepath.Dir(info), 0o700); err != nil {
		return "", err
	}
	body := "[Trash Info]\nPath=" + (&url.URL{Path: path}).EscapedPath() + "\nDeletionDate=" + m.Now().Format("2006-01-02T15:04:05") + "\n"
	f, err := os.OpenFile(info, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	_, err = f.WriteString(body)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return "", errors.Join(err, os.Remove(info))
	}
	return info, nil
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
