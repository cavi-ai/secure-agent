package worktreehunter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	var notReviewable *NotReviewableError
	if _, err := h.TrashReviewed(ctx, wt, row.Head, row.Reasons); !errors.As(err, &notReviewable) || notReviewable.Row.State != StateKeep {
		t.Fatalf("new untracked file: %v", err)
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
