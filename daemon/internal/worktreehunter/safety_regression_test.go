package worktreehunter

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTrashReviewedRefusesResolvedMerge(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	wt := f.worktree(t, "audit-merge")
	commit(t, wt, "branch.txt", "branch\n", "branch")
	commit(t, f.main, "main.txt", "main\n", "main")
	run(t, wt, "merge", "--no-commit", "--no-ff", "main")
	admin := run(t, wt, "rev-parse", "--absolute-git-dir")
	if _, err := os.Stat(filepath.Join(admin, "MERGE_HEAD")); err != nil {
		t.Fatal(err)
	}
	h := New(newMemStore(), home, Options{})
	h.goos = "darwin"
	h.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	row, _, err := h.Inspect(context.Background(), wt)
	if err != nil {
		t.Fatal(err)
	}
	if row.Conflicts != 0 || row.PartlyStaged != 0 {
		t.Fatalf("unexpected fixture: %+v", row)
	}
	_, err = h.TrashReviewed(context.Background(), wt, row.Head, row.Reasons)
	if err == nil {
		t.Fatal("unfinished merge was moved to Trash")
	}
	if _, err := os.Stat(filepath.Join(admin, "MERGE_HEAD")); err != nil {
		t.Fatal("merge metadata lost:", err)
	}
	if _, err := os.Stat(filepath.Join(wt, "main.txt")); err != nil {
		t.Fatal("working files moved:", err)
	}

}

func TestGitOperationsBlockAllRemoval(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	wt := f.worktree(t, "operation")
	admin := run(t, wt, "rev-parse", "--absolute-git-dir")
	h := New(newMemStore(), home, Options{})
	h.goos = "darwin"
	h.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	// Synthetic marker fixtures cover operation states independently of
	// unmerged index entries; the resolved merge above uses a real operation.
	for _, marker := range []string{"MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "rebase-merge", "rebase-apply", "sequencer", "BISECT_START"} {
		t.Run(marker, func(t *testing.T) {
			p := filepath.Join(admin, marker)
			if err := os.WriteFile(p, []byte("operation\n"), 0600); err != nil {
				t.Fatal(err)
			}
			defer os.Remove(p)
			row, _, err := h.Inspect(context.Background(), wt)
			if err != nil || row.State != StateKeep || row.Operation == "" {
				t.Fatalf("operation inspection: %+v %v", row, err)
			}
			if _, err = h.Remove(context.Background(), wt); err == nil {
				t.Fatal("automatic removal admitted operation")
			}
			if _, err = h.TrashReviewed(context.Background(), wt, row.Head, row.Reasons); err == nil || !strings.Contains(err.Error(), "in progress") {
				t.Fatalf("reviewed removal admitted operation: %v", err)
			}
		})
	}
}
func TestContentSimilarityDoesNotProveMerge(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	wt := f.worktree(t, "audit-order")
	commit(t, wt, "flow.py", "def handle(user):\n    check_permission(user)\n    delete_record(user)\n", "authorize before action")
	commit(t, f.main, "flow.py", "def handle(user):\n    delete_record(user)\n    check_permission(user)\n", "action before authorization")
	run(t, f.main, "push", "-q", "origin", "main")
	h := New(newMemStore(), home, Options{})
	h.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	row, _, err := h.Inspect(context.Background(), wt)
	if err != nil {
		t.Fatal(err)
	}
	if isMerged(row.Merged) || row.State != StateReview {
		t.Fatalf("unordered content was treated as merged: merged=%s state=%s", row.Merged, row.State)
	}
}
