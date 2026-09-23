package worktreehunter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func TestRemoveOnlyOnFreshRemoveVerdict(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	ctx := context.Background()

	merged := f.worktree(t, "merged")
	commit(t, merged, "a.txt", "a\n", "a")
	run(t, f.main, "merge", "-q", "--no-ff", "-m", "merge a", "feat/merged")
	run(t, f.main, "push", "-q", "origin", "main")

	dirty := f.worktree(t, "dirty")
	write(t, filepath.Join(dirty, "base.txt"), "edited\n")

	env := f.worktree(t, "env")
	write(t, filepath.Join(env, ".env"), "K=[REDACTED]\n")

	racy := f.worktree(t, "racy")

	st := newMemStore()
	st.activity = []model.WorkspaceActivity{{Workspace: f.main}}
	h := New(st, home, Options{})
	h.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	rep := h.Report(ctx, true)
	wantState(t, findRow(t, rep, racy), StateRemove, "")

	// Work lands after the scan: the fresh inspection refuses.
	write(t, filepath.Join(racy, "late.txt"), "late\n")
	var nr *NotRemovableError
	if _, err := h.Remove(ctx, racy); !errors.As(err, &nr) || nr.Row.State != StateKeep {
		t.Fatalf("Remove(racy after new file) err = %v, want NotRemovableError keep", err)
	}
	if !exists(filepath.Join(racy, "late.txt")) {
		t.Fatal("refused removal deleted the file")
	}

	for _, p := range []string{dirty, env} {
		if _, err := h.Remove(ctx, p); !errors.As(err, &nr) {
			t.Fatalf("Remove(%s) err = %v, want NotRemovableError", filepath.Base(p), err)
		}
		if !exists(p) {
			t.Fatalf("refused removal deleted %s", p)
		}
	}
	if _, err := h.Remove(ctx, f.main); !errors.Is(err, ErrNotWorktree) {
		t.Fatalf("Remove(main) err = %v, want ErrNotWorktree", err)
	}
	if _, err := h.Remove(ctx, f.root); !errors.Is(err, ErrNotWorktree) {
		t.Fatalf("Remove(non-repo) err = %v, want ErrNotWorktree", err)
	}
	if _, err := h.Remove(ctx, "relative"); err == nil {
		t.Fatal("relative path accepted")
	}

	row, err := h.Remove(ctx, merged)
	if err != nil {
		t.Fatalf("Remove(merged): %v", err)
	}
	if row.State != StateRemove || exists(merged) {
		t.Fatalf("merged not removed: state %s, exists %v", row.State, exists(merged))
	}
	if strings.Contains(run(t, f.main, "worktree", "list", "--porcelain"), merged) {
		t.Fatal("git still lists the removed worktree")
	}
	if run(t, f.main, "rev-parse", "--verify", "--quiet", "refs/heads/feat/merged") == "" {
		t.Fatal("removal deleted the branch")
	}
	if len(st.audit) != 1 || st.audit[0].Action != "worktree-remove" || !strings.Contains(st.audit[0].Detail, "branch=feat/merged") {
		t.Fatalf("audit = %+v", st.audit)
	}
	if rep := h.Report(ctx, false); rep.Cached {
		t.Fatal("removal did not drop the cached report")
	}
}

func TestPrune(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	ctx := context.Background()
	st := newMemStore()
	h := New(st, home, Options{})

	if _, err := h.Prune(ctx, f.main); !errors.Is(err, ErrNothingToPrune) {
		t.Fatalf("Prune(clean repo) err = %v, want ErrNothingToPrune", err)
	}

	gone := f.worktree(t, "gone")
	lockedGone := f.worktree(t, "locked-gone")
	run(t, f.main, "worktree", "lock", lockedGone)
	for _, p := range []string{gone, lockedGone} {
		if err := os.RemoveAll(p); err != nil {
			t.Fatal(err)
		}
	}

	st.activity = []model.WorkspaceActivity{{Workspace: f.main}}
	rep := h.Report(ctx, true)
	wantState(t, findRow(t, rep, gone), StatePrune, "")
	wantState(t, findRow(t, rep, lockedGone), StateKeep, "unlock it to prune")

	pruned, err := h.Prune(ctx, filepath.Join(f.main, "sub"))
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(pruned) != 1 || pruned[0] != gone {
		t.Fatalf("pruned = %v, want only %s", pruned, gone)
	}
	list := run(t, f.main, "worktree", "list", "--porcelain")
	if strings.Contains(list, gone+"\n") || !strings.Contains(list, lockedGone) {
		t.Fatalf("after prune:\n%s", list)
	}
	if len(st.audit) != 1 || st.audit[0].Action != "worktree-prune" {
		t.Fatalf("audit = %+v", st.audit)
	}
	if _, err := h.Prune(ctx, f.root); !errors.Is(err, ErrNotRepo) {
		t.Fatalf("Prune(non-repo) err = %v, want ErrNotRepo", err)
	}
}

func TestAdviceRequest(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	ctx := context.Background()

	wt := f.worktree(t, "wip")
	commit(t, wt, "a.txt", "a\n", "add the parser")
	commit(t, wt, "b.txt", "b\n", "wire the parser")
	write(t, filepath.Join(wt, "scratch.txt"), "s\n")
	write(t, filepath.Join(wt, ".env"), "K=[REDACTED]\n")
	gone := f.worktree(t, "gone")
	if err := os.RemoveAll(gone); err != nil {
		t.Fatal(err)
	}

	h := New(newMemStore(), home, Options{})
	req, err := h.AdviceRequest(ctx, wt)
	if err != nil {
		t.Fatal(err)
	}
	if req.State != StateKeep || req.Branch != "feat/wip" || req.Head == "" || req.Path != wt {
		t.Fatalf("request = %+v", req)
	}
	if strings.Join(req.Commits, "|") != "wire the parser|add the parser" {
		t.Fatalf("commits = %q", req.Commits)
	}
	if strings.Join(req.Paths, "|") != "scratch.txt" || len(req.Precious) != 1 || !strings.HasPrefix(req.Precious[0], ".env") {
		t.Fatalf("paths = %q precious = %q", req.Paths, req.Precious)
	}
	if _, err := h.AdviceRequest(ctx, gone); !errors.Is(err, ErrNothingToAdvise) {
		t.Fatalf("gone: err = %v, want ErrNothingToAdvise", err)
	}
	if _, err := h.AdviceRequest(ctx, f.main); !errors.Is(err, ErrNotWorktree) {
		t.Fatalf("main: err = %v, want ErrNotWorktree", err)
	}
}
