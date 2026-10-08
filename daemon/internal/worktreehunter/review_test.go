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

func TestTrashReviewedPreservesFilesAndGitHistory(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	wt := f.worktree(t, "review")
	commit(t, wt, "work.txt", "local commit\n", "local work")
	write(t, filepath.Join(wt, ".env"), "TOKEN=[REDACTED]\n")
	h := New(newMemStore(), home, Options{})
	h.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	h.goos = "darwin"
	ctx := context.Background()
	row, _, err := h.Inspect(ctx, wt)
	if err != nil || row.State != StateReview {
		t.Fatalf("review row = %+v, %v", row, err)
	}
	if _, err := h.TrashReviewed(ctx, wt, "stale", row.Reasons); !errors.Is(err, ErrReviewChanged) {
		t.Fatalf("stale head: %v", err)
	}
	write(t, filepath.Join(wt, "new.txt"), "untracked\n")
	if _, err := h.TrashReviewed(ctx, wt, row.Head, row.Reasons); !errors.Is(err, ErrReviewChanged) {
		t.Fatalf("new untracked file changes the reasons: %v", err)
	}
	if err := os.Remove(filepath.Join(wt, "new.txt")); err != nil {
		t.Fatal(err)
	}
	row, _, err = h.Inspect(ctx, wt)
	if err != nil || row.State != StateReview {
		t.Fatalf("fresh review row = %+v, %v", row, err)
	}
	result, err := h.TrashReviewed(ctx, wt, row.Head, row.Reasons)
	if err != nil {
		t.Fatal(err)
	}
	if exists(wt) || !exists(filepath.Join(result.TrashPath, ".env")) || !exists(filepath.Join(result.TrashPath, "work.txt")) {
		t.Fatalf("folder not preserved in Trash: %+v", result)
	}
	if strings.Contains(run(t, f.main, "worktree", "list", "--porcelain"), wt) {
		t.Fatal("git still lists reviewed worktree")
	}
	if run(t, f.main, "rev-parse", "--verify", "refs/heads/feat/review") == "" {
		t.Fatal("branch was lost")
	}
}

func TestTrashReviewedMovesKeepRowWithUncommittedWork(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	wt := f.worktree(t, "dirty")
	write(t, filepath.Join(wt, "base.txt"), "edited\n")
	write(t, filepath.Join(wt, "scratch.txt"), "untracked\n")
	h := New(newMemStore(), home, Options{})
	h.goos = "darwin"
	ctx := context.Background()
	row, _, err := h.Inspect(ctx, wt)
	if err != nil || row.State != StateKeep || row.Changed != 1 || row.Untracked != 1 {
		t.Fatalf("keep row = %+v, %v", row, err)
	}
	result, err := h.TrashReviewed(ctx, wt, row.Head, row.Reasons)
	if err != nil {
		t.Fatal(err)
	}
	if exists(wt) {
		t.Fatal("folder still in place")
	}
	if got, err := os.ReadFile(filepath.Join(result.TrashPath, "base.txt")); err != nil || string(got) != "edited\n" {
		t.Fatalf("modified file in Trash = %q, %v", got, err)
	}
	if !exists(filepath.Join(result.TrashPath, "scratch.txt")) {
		t.Fatal("untracked file missing from the Trash copy")
	}
	if strings.Contains(run(t, f.main, "worktree", "list", "--porcelain"), wt) {
		t.Fatal("git still lists the worktree")
	}
	if run(t, f.main, "rev-parse", "--verify", "refs/heads/feat/dirty") == "" {
		t.Fatal("branch was lost")
	}
}

func TestTrashReviewedRefusesWhatTheFolderMoveCannotUndo(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, f fixture, st *memStore) string
		why   string
	}{
		{"agent session live", func(t *testing.T, f fixture, st *memStore) string {
			wt := f.worktree(t, "in-use")
			st.activity = []model.WorkspaceActivity{{Workspace: wt, LastSeen: time.Now(), Live: true}}
			return wt
		}, "an agent session is live here"},
		{"locked", func(t *testing.T, f fixture, st *memStore) string {
			wt := f.worktree(t, "locked")
			run(t, f.main, "worktree", "lock", "--reason", "agent busy", wt)
			return wt
		}, "it is locked; unlock it first"},
		{"detached with loose commits", func(t *testing.T, f fixture, st *memStore) string {
			wt := filepath.Join(f.main, ".worktrees", "detached")
			run(t, f.main, "worktree", "add", "-q", "--detach", wt, "main")
			commit(t, wt, "g.txt", "g\n", "g")
			return wt
		}, "detached HEAD has commits on no branch; create a branch first"},
		// git deletes the worktree's index with it: a staged version the
		// working file no longer has would be lost, not moved to the Trash.
		{"partly staged", func(t *testing.T, f fixture, st *memStore) string {
			wt := f.worktree(t, "staged")
			write(t, filepath.Join(wt, "base.txt"), "staged version\n")
			run(t, wt, "add", "base.txt")
			write(t, filepath.Join(wt, "base.txt"), "working version\n")
			return wt
		}, "1 file has staged changes that differ from the working copy; commit or unstage them first"},
		{"staged then deleted", func(t *testing.T, f fixture, st *memStore) string {
			wt := f.worktree(t, "staged-gone")
			write(t, filepath.Join(wt, "gone.txt"), "only in the index\n")
			run(t, wt, "add", "gone.txt")
			if err := os.Remove(filepath.Join(wt, "gone.txt")); err != nil {
				t.Fatal(err)
			}
			return wt
		}, "1 file has staged changes that differ from the working copy; commit or unstage them first"},
		{"merge conflict", func(t *testing.T, f fixture, st *memStore) string {
			wt := f.worktree(t, "conflict")
			commit(t, wt, "base.txt", "branch side\n", "branch edit")
			commit(t, f.main, "base.txt", "main side\n", "main edit")
			// The merge stops on the conflict; its exit status is expected.
			_ = gitCommand(context.Background(), wt, "merge", "-q", "main").Run()
			return wt
		}, "a merge or rebase has unresolved conflicts; finish or abort it first"},
		{"nested registered worktree", func(t *testing.T, f fixture, st *memStore) string {
			wt := f.worktree(t, "outer")
			run(t, f.main, "worktree", "add", "-q", "-b", "feat/inner", filepath.Join(wt, "inner"), "main")
			return wt
		}, "another registered worktree is inside this folder"},
		{"remove row", func(t *testing.T, f fixture, st *memStore) string {
			wt := f.worktree(t, "merged")
			commit(t, wt, "a.txt", "a\n", "a")
			run(t, f.main, "merge", "-q", "--no-ff", "-m", "merge a", "feat/merged")
			run(t, f.main, "push", "-q", "origin", "main")
			return wt
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := isolateGit(t)
			f := newFixture(t)
			st := newMemStore()
			wt := tc.setup(t, f, st)
			h := New(st, home, Options{})
			h.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
			h.goos = "darwin"
			ctx := context.Background()
			row, _, err := h.Inspect(ctx, wt)
			if err != nil {
				t.Fatal(err)
			}
			if tc.why == "" && row.State != StateRemove {
				t.Fatalf("fixture row = %s, want remove", row.State)
			}
			_, err = h.TrashReviewed(ctx, wt, row.Head, row.Reasons)
			var notReviewable *NotReviewableError
			if !errors.As(err, &notReviewable) {
				t.Fatalf("state %s: err = %v, want NotReviewableError", row.State, err)
			}
			if notReviewable.Why != tc.why || !strings.Contains(err.Error(), tc.why) {
				t.Fatalf("why = %q (%v), want %q", notReviewable.Why, err, tc.why)
			}
			if !exists(wt) || !strings.Contains(run(t, f.main, "worktree", "list", "--porcelain"), wt) {
				t.Fatal("refused row was moved or unregistered")
			}
		})
	}
}
