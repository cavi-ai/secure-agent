package worktreehunter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/diskusage"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
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

// removeTimeout bounds `git worktree remove`, which deletes the whole
// tree: 200,000 files take 16 s on an external disk, past gitTimeout.
const removeTimeout = 10 * time.Minute

// Remove inspects path again now and runs `git worktree remove` (never
// --force) only when that fresh verdict is remove. The branch and every
// commit stay; git itself still refuses a tree that turned dirty in between.
// It holds the scan lock, so no scan interleaves with a removal, and it
// finishes even when ctx is canceled: a half-deleted worktree is worse than
// a late answer. Its progress shows in Removals.
func (h *Hunter) Remove(ctx context.Context, path string) (Worktree, error) {
	if !filepath.IsAbs(path) {
		return Worktree{}, errors.New("path must be absolute")
	}
	job, err := h.beginRemoval(path)
	if err != nil {
		return Worktree{}, err
	}
	row, err := h.remove(context.WithoutCancel(ctx), path, job.step)
	job.finish(row, err)
	return row, err
}

func (h *Hunter) remove(ctx context.Context, path string, step func(string)) (Worktree, error) {
	if !h.scanMu.TryLock() {
		step(StepWaiting)
		h.scanMu.Lock()
	}
	defer h.scanMu.Unlock()

	step(StepChecking)
	rs, l, err := h.locate(ctx, path)
	if err != nil {
		return Worktree{}, err
	}
	row := h.judge(ctx, rs, l)
	if row.State != StateRemove {
		return row, &NotRemovableError{Row: row}
	}
	// Measured now, not from the cache: this is the space the ledger books.
	step(StepMeasuring)
	skip := map[string]bool{}
	for _, o := range rs.list {
		if o.Path != l.Path {
			skip[o.Path] = true
		}
	}
	u := diskusage.Dir(ctx, l.Path, skip)
	row.SizeBytes, row.SizePartial = u.Bytes, u.Partial
	step(StepDeleting)
	if _, err := gitWithin(ctx, removeTimeout, rs.ref.Main, "worktree", "remove", l.Path); err != nil {
		if _, statErr := os.Stat(l.Path); statErr == nil {
			return row, fmt.Errorf("%w (the worktree is still on disk and registered with git)", err)
		}
		return row, err
	}
	h.st.PutAudit(store.AuditEntry{
		Action: "worktree-remove",
		Detail: fmt.Sprintf("path=%s branch=%s head=%s reason=%s", l.Path, orDetached(l.Branch), shortSHA(l.Head), strings.Join(row.Reasons, "; ")),
	})
	h.st.PutCleanup(model.CleanupEntry{
		TS: h.now(), Action: "worktree-remove", Path: l.Path, Repo: rs.ref.Main, Bytes: row.SizeBytes,
		Detail: "branch " + orDetached(l.Branch) + " kept; " + strings.Join(row.Reasons, "; "),
	})
	h.forgetSize(l.Path)
	h.dropRow(l.Path)
	return row, nil
}

// dropRow takes a removed worktree out of the cached scan, with the group
// and error line of a missing repository it leaves empty, and marks the
// scan old, so the next report answers without it while a background
// rescan confirms.
func (h *Hunter) dropRow(path string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cached == nil {
		return
	}
	rep := *h.cached
	rep.Repos = nil
	gone := map[string]bool{}
	for _, r := range h.cached.Repos {
		kept := make([]Worktree, 0, len(r.Worktrees))
		for _, w := range r.Worktrees {
			if w.Path != path {
				kept = append(kept, w)
			}
		}
		if r.Error == ErrRepoMissing && len(kept) == 0 {
			gone[r.Path] = true
			continue
		}
		r.Worktrees = kept
		rep.Repos = append(rep.Repos, r)
	}
	rep.Errors = nil
	for _, e := range h.cached.Errors {
		if repo, _, _ := strings.Cut(e, ": "); !gone[repo] {
			rep.Errors = append(rep.Errors, e)
		}
	}
	rep.Summary = summarize(rep.Repos)
	h.cached, h.cachedAt = &rep, time.Time{}
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
	for _, p := range gone {
		h.st.PutCleanup(model.CleanupEntry{TS: h.now(), Action: "worktree-prune", Path: p, Repo: ref.Main, Detail: "directory was already gone"})
	}
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
