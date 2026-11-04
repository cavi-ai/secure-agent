package clutter

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cavi-ai/secure-agent/daemon/internal/diskusage"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func regularFile(path string) bool {
	st, err := os.Lstat(path)
	return err == nil && st.Mode().IsRegular()
}

// A stale editor record is harmless; a live PID or an unreadable record
// keeps the cache protected even when no agent session is running.
func unityCacheBusy(path string) bool {
	if filepath.Base(path) != "Library" {
		return false
	}
	b, err := os.ReadFile(filepath.Join(path, "EditorInstance.json"))
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	var editor struct {
		PID int `json:"process_id"`
	}
	if err != nil || json.Unmarshal(b, &editor) != nil || editor.PID <= 0 {
		return true
	}
	return !errors.Is(syscall.Kill(editor.PID, 0), syscall.ESRCH)
}

// Inspect only the owning workspace. Deleting one cache must not rescan and
// run Git checks in every other repository on the machine.
func (c *Clutter) removableCache(ctx context.Context, path string) (ClutterItem, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ClutterItem{}, ErrNotInInventory
	}
	places := c.places(ctx)
	placeSet := map[string]bool{}
	var owner Place
	for _, p := range places {
		placeSet[p.Path] = true
		if strings.HasPrefix(path, p.Path+string(filepath.Separator)) && len(p.Path) > len(owner.Path) {
			owner = p
		}
	}
	if owner.Path == "" || livePlaces(places, c.st.WorkspaceActivity(), c.now())[owner.Path] || unityCacheBusy(path) {
		return ClutterItem{}, ErrNotInInventory
	}
	for _, candidate := range search(owner.Path, placeSet) {
		if candidate.path != path || candidate.kind != KindRepoCache {
			continue
		}
		ok, err := disposable(ctx, owner.Path, []string{path})
		if err != nil {
			return ClutterItem{}, err
		}
		if ok[path] {
			return ClutterItem{ID: KindRepoCache + ":" + path, Kind: KindRepoCache, Name: filepath.Base(path),
				Path: path, Project: owner.Project, Worktree: owner.Worktree, Action: ActionTrash, CanRemove: true}, nil
		}
	}
	return ClutterItem{}, ErrNotInInventory
}

// Remove permanently deletes only an ignored, untracked repository cache.
// Scratch files, quarantine, app caches and worktree roots retain their
// existing Trash-only behavior.
func (c *Clutter) Remove(ctx context.Context, path string) (ClutterResult, error) {
	c.scanMu.Lock()
	defer c.scanMu.Unlock()
	it, err := c.removableCache(ctx, path)
	if err != nil {
		return ClutterResult{}, err
	}
	if !it.CanRemove {
		return ClutterResult{}, ErrNotInInventory
	}
	st, err := os.Lstat(it.Path)
	if err != nil || !st.IsDir() {
		return ClutterResult{}, ErrChanged
	}
	u := diskusage.Dir(ctx, it.Path, nil)
	if err := ctx.Err(); err != nil {
		return ClutterResult{}, err
	}
	// Measuring a large cache can take time. Recheck Git and activity at
	// the target immediately before deletion, including nested worktrees.
	places := c.places(ctx)
	live := livePlaces(places, c.st.WorkspaceActivity(), c.now())
	place := it.Worktree
	if place == "" {
		place = it.Project
	}
	for _, p := range places {
		if p.Path == it.Path || strings.HasPrefix(p.Path, it.Path+string(filepath.Separator)) {
			return ClutterResult{}, ErrChanged
		}
	}
	registered, err := runGit(ctx, place, "", "worktree", "list", "--porcelain", "-z")
	if err != nil {
		return ClutterResult{}, err
	}
	for _, field := range strings.Split(registered, "\x00") {
		if nested, ok := strings.CutPrefix(field, "worktree "); ok && (nested == it.Path || strings.HasPrefix(nested, it.Path+string(filepath.Separator))) {
			return ClutterResult{}, ErrChanged
		}
	}
	ok, err := disposable(ctx, place, []string{it.Path})
	if err != nil {
		return ClutterResult{}, err
	}
	if !ok[it.Path] || live[place] || unityCacheBusy(it.Path) {
		return ClutterResult{}, ErrChanged
	}
	// Anchor deletion to an open parent directory so replacing an ancestor
	// with a symlink cannot redirect it outside that directory.
	root, err := os.OpenRoot(filepath.Dir(it.Path))
	if err != nil {
		return ClutterResult{}, err
	}
	defer root.Close()
	name := filepath.Base(it.Path)
	current, err := root.Lstat(name)
	if err != nil || !os.SameFile(st, current) {
		return ClutterResult{}, ErrChanged
	}
	if err := ctx.Err(); err != nil {
		return ClutterResult{}, err
	}
	defer c.forgetSize(it.Path)
	defer c.invalidate()
	if err := root.RemoveAll(name); err != nil {
		return ClutterResult{}, err
	}
	c.st.PutCleanup(model.CleanupEntry{TS: c.now(), Action: "clean:build-cache", Path: it.Path, Repo: it.Project,
		Bytes: u.Bytes, Detail: "permanently removed regenerable build cache"})
	return ClutterResult{Item: it, Bytes: u.Bytes, Partial: u.Partial}, nil
}
