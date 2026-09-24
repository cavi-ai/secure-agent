package clutter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/diskusage"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

var (
	// ErrNotInInventory is returned for a path or tool the current
	// inventory does not offer that action for.
	ErrNotInInventory = errors.New("not in the current cleanup inventory with that action")
	// ErrChanged is returned when the item is no longer what the inventory
	// listed (gone, or replaced by a symlink).
	ErrChanged = errors.New("the item changed since the inventory; rescan")
)

// cleanTimeout bounds one tool clean command.
const cleanTimeout = 10 * time.Minute

// Result is what one action gave back.
type Result struct {
	Item    Item   `json:"item"`
	Bytes   int64  `json:"bytes"`
	Partial bool   `json:"bytes_partial,omitempty"`
	TrashAt string `json:"trash_path,omitempty"`
	Output  string `json:"output,omitempty"` // the clean command's last lines
}

// Trash moves one inventory item to the Trash on its own volume and books
// its size in the ledger as trashed (the space frees when the Trash is
// emptied).
func (c *Clutter) Trash(ctx context.Context, path string) (Result, error) {
	c.scanMu.Lock()
	defer c.scanMu.Unlock()
	it, err := c.findLocked(ctx, path, ActionTrash)
	if err != nil {
		return Result{}, err
	}
	st, err := os.Lstat(it.Path)
	if err != nil || !st.IsDir() {
		return Result{}, ErrChanged
	}
	u := diskusage.Dir(ctx, it.Path, nil)
	dest, err := c.moveToTrash(it.Path)
	if err != nil {
		return Result{}, err
	}
	c.st.PutCleanup(model.CleanupEntry{
		TS: c.now(), Action: "trash:" + it.Kind, Path: it.Path, Repo: it.Project, Bytes: u.Bytes,
		Detail: "moved to " + dest,
	})
	c.forgetSize(it.Path)
	c.invalidate()
	return Result{Item: it, Bytes: u.Bytes, Partial: u.Partial, TrashAt: dest}, nil
}

// Clean runs a tool cache's own clean command and books what the cache
// shrank by.
func (c *Clutter) Clean(ctx context.Context, name string) (Result, error) {
	c.scanMu.Lock()
	defer c.scanMu.Unlock()
	it, err := c.findLocked(ctx, name, ActionClean)
	if err != nil {
		return Result{}, err
	}
	var tc toolCache
	for _, t := range toolCaches(c.home, c.goos) {
		if t.name == it.Name {
			tc = t
		}
	}
	bin := lookTool(tc.command[0], c.binDirs)
	if bin == "" {
		return Result{}, fmt.Errorf("%s is not installed", tc.command[0])
	}
	before := diskusage.Dir(ctx, it.Path, nil)
	cctx, cancel := context.WithTimeout(ctx, cleanTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, tc.command[1:]...)
	cmd.Dir = c.home
	// The tool's own directory first (npm needs its node), then the install
	// directories, then the daemon's PATH and the system directories.
	path := append(append([]string{filepath.Dir(bin)}, c.binDirs...), os.Getenv("PATH"), "/usr/bin", "/bin")
	cmd.Env = append(os.Environ(), "PATH="+strings.Join(path, ":"))
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	runErr := cmd.Run()
	after := diskusage.Dir(ctx, it.Path, nil)
	freed := before.Bytes - after.Bytes
	if freed < 0 {
		freed = 0
	}
	res := Result{Item: it, Bytes: freed, Partial: before.Partial || after.Partial, Output: tail(out.String(), 5)}
	if runErr != nil {
		return res, fmt.Errorf("%s: %v: %s", it.Command, runErr, res.Output)
	}
	c.st.PutCleanup(model.CleanupEntry{
		TS: c.now(), Action: "clean:" + it.Name, Path: it.Path, Bytes: freed, Detail: it.Command,
	})
	c.putSize(it.Path, after)
	c.invalidate()
	return res, nil
}

// findLocked rebuilds the inventory now (the caller holds scanMu) and
// returns key's item when it offers action: a session that went live, or a
// directory that went away, since the last report is seen here.
func (c *Clutter) findLocked(ctx context.Context, key, action string) (Item, error) {
	items := c.collect(ctx)
	rep := ClutterReport{GeneratedAt: c.now().UTC(), Items: items}
	c.mu.Lock()
	c.cached, c.cachedAt = &rep, c.now()
	c.mu.Unlock()
	for _, it := range items {
		if it.Action == action && (it.Path == key || (action == ActionClean && it.Name == key)) {
			return it, nil
		}
	}
	return Item{}, ErrNotInInventory
}

// moveToTrash renames path into the Trash on its own volume: ~/.Trash for
// the home volume, <volume>/.Trashes/<uid> for others (what Finder uses).
// A name already in the Trash gets a time suffix, as Finder does.
func (c *Clutter) moveToTrash(path string) (string, error) {
	dir, err := c.trashDir(path)
	if err != nil {
		return "", err
	}
	dest := filepath.Join(dir, filepath.Base(path))
	if _, err := os.Lstat(dest); err == nil {
		dest = filepath.Join(dir, filepath.Base(path)+" "+c.now().Format("15.04.05.000"))
	}
	if err := os.Rename(path, dest); err != nil {
		return "", fmt.Errorf("move to Trash: %w", err)
	}
	return dest, nil
}

func (c *Clutter) trashDir(path string) (string, error) {
	if c.goos != "darwin" {
		dir := filepath.Join(c.home, ".local", "share", "Trash", "files")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		if !diskusage.SameDevice(dir, path) {
			return "", errors.New("the Trash is on another volume")
		}
		return dir, nil
	}
	home := filepath.Join(c.home, ".Trash")
	if diskusage.SameDevice(c.home, path) {
		return home, os.MkdirAll(home, 0o700)
	}
	dir := filepath.Join(diskusage.Root(path), ".Trashes", strconv.Itoa(os.Getuid()))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("volume Trash: %w", err)
	}
	return dir, nil
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
