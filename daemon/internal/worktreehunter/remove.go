package worktreehunter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

var (
	// ErrNotWorktree is returned for a path that is not a linked worktree
	// git lists (the main worktree included).
	ErrNotWorktree = errors.New("not a linked worktree of a repository git knows")
	// ErrNothingToPrune is returned when a repository lists no worktree
	// whose directory is gone.
	ErrNothingToPrune = errors.New("no worktree of this repository has a missing directory")
)

// NotRemovableError refuses a removal: the fresh verdict is not remove.
type NotRemovableError struct {
	Row Worktree
}

func (e *NotRemovableError) Error() string {
	return fmt.Sprintf("worktree is %s, not remove: %s", e.Row.State, strings.Join(e.Row.Reasons, "; "))
}

// Remove inspects path again now and runs `git worktree remove` (never
// --force) only when that fresh verdict is remove. The branch and every
// commit stay; git itself still refuses a tree that turned dirty in between.
// It holds the scan lock, so no scan interleaves with a removal.
func (h *Hunter) Remove(ctx context.Context, path string) (Worktree, error) {
	if !filepath.IsAbs(path) {
		return Worktree{}, errors.New("path must be absolute")
	}
	h.scanMu.Lock()
	defer h.scanMu.Unlock()

	rs, l, err := h.locate(ctx, path)
	if err != nil {
		return Worktree{}, err
	}
	row := h.judge(ctx, rs, l)
	if row.State != StateRemove {
		return row, &NotRemovableError{Row: row}
	}
	if _, err := git(ctx, rs.ref.Main, "worktree", "remove", l.Path); err != nil {
		return row, err
	}
	h.st.PutAudit(store.AuditEntry{
		Action: "worktree-remove",
		Detail: fmt.Sprintf("path=%s branch=%s head=%s reason=%s", l.Path, orDetached(l.Branch), shortSHA(l.Head), strings.Join(row.Reasons, "; ")),
	})
	h.invalidate()
	return row, nil
}

// Prune runs `git worktree prune` in the repository containing repo when it
// lists at least one unlocked worktree whose directory is gone, and returns
// those paths.
func (h *Hunter) Prune(ctx context.Context, repo string) ([]string, error) {
	if !filepath.IsAbs(repo) {
		return nil, errors.New("path must be absolute")
	}
	h.scanMu.Lock()
	defer h.scanMu.Unlock()

	ref, _, ok := resolveRepo(repo)
	if !ok {
		return nil, ErrNotRepo
	}
	list, err := listWorktrees(ctx, ref.Main)
	if err != nil {
		return nil, err
	}
	var gone []string
	for i, l := range list {
		if i == 0 || l.Bare || l.Locked {
			continue
		}
		if _, err := os.Stat(l.Path); err != nil || l.Prunable {
			gone = append(gone, l.Path)
		}
	}
	if len(gone) == 0 {
		return nil, ErrNothingToPrune
	}
	if _, err := git(ctx, ref.Main, "worktree", "prune"); err != nil {
		return nil, err
	}
	h.st.PutAudit(store.AuditEntry{
		Action: "worktree-prune",
		Detail: fmt.Sprintf("repo=%s pruned=%s", ref.Main, strings.Join(gone, ",")),
	})
	h.invalidate()
	return gone, nil
}

// locate finds path among its repository's linked worktrees.
func (h *Hunter) locate(ctx context.Context, path string) (*repoScan, listed, error) {
	ref, _, ok := resolveRepo(path)
	if !ok {
		return nil, listed{}, ErrNotWorktree
	}
	rs := &repoScan{ref: ref, out: &RepoReport{Path: ref.Main}}
	h.prepareRepo(ctx, rs)
	if rs.out.Error != "" {
		return nil, listed{}, errors.New(rs.out.Error)
	}
	want := canonical(path)
	for i, l := range rs.list {
		if i > 0 && !l.Bare && canonical(l.Path) == want {
			return rs, l, nil
		}
	}
	return nil, listed{}, ErrNotWorktree
}

// judge inspects one worktree and classifies it with the current options.
func (h *Hunter) judge(ctx context.Context, rs *repoScan, l listed) Worktree {
	opts := h.Options()
	w, f := h.inspectOne(ctx, rs, false, l, h.st.WorkspaceActivity())
	classify(&w, f, h.now(), staleDuration(opts.StaleDays))
	return w
}

func orDetached(branch string) string {
	if branch == "" {
		return "(detached)"
	}
	return branch
}
