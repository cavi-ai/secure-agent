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

func TestRemoveReviewedScratchKeepsCommittedWork(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	wt := f.worktree(t, "scratch-review")
	commit(t, wt, "work.txt", "local committed source\n", "local source")
	head := run(t, wt, "rev-parse", "HEAD")
	write(t, filepath.Join(wt, ".tmp", "test.log"), "temporary output\n")
	h := New(newMemStore(), home, Options{})
	h.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	ctx := context.Background()
	row, _, err := h.Inspect(ctx, wt)
	if err != nil || row.State != StateReview || !row.CanRemoveReviewed {
		t.Fatalf("review eligibility: %+v, %v", row, err)
	}
	if _, err := h.Remove(ctx, wt); err == nil {
		t.Fatal("automatic removal discarded unreviewed scratch")
	}
	if _, err := h.RemoveReviewed(ctx, wt, RemovalReview{Head: "stale", Reasons: row.Reasons}); !errors.Is(err, ErrReviewChanged) {
		t.Fatalf("stale review: %v", err)
	}
	if _, err := h.RemoveReviewed(ctx, wt, RemovalReview{Head: row.Head, Reasons: row.Reasons}); err != nil {
		t.Fatal(err)
	}
	if exists(wt) || strings.Contains(run(t, f.main, "worktree", "list", "--porcelain"), wt) {
		t.Fatal("reviewed worktree was not removed")
	}
	if got := run(t, f.main, "show", "refs/heads/feat/scratch-review:work.txt"); got != "local committed source" {
		t.Fatalf("committed source was not retained: %q", got)
	}
	if run(t, f.main, "rev-parse", "refs/heads/feat/scratch-review") != head {
		t.Fatal("branch changed during removal")
	}
}

func TestRemoveReviewedPreservesNewSourceAndNestedSecrets(t *testing.T) {
	for _, name := range []string{"untracked", "tracked", "nested secret"} {
		t.Run(name, func(t *testing.T) {
			home := isolateGit(t)
			f := newFixture(t)
			wt := f.worktree(t, "protected")
			commit(t, wt, "work.txt", "source\n", "local source")
			write(t, filepath.Join(wt, ".tmp", "test.log"), "scratch\n")
			h := New(newMemStore(), home, Options{})
			ctx := context.Background()
			row, _, err := h.Inspect(ctx, wt)
			if err != nil || !row.CanRemoveReviewed {
				t.Fatalf("initial row: %+v %v", row, err)
			}
			path := filepath.Join(wt, "new.txt")
			switch name {
			case "tracked":
				path = filepath.Join(wt, "work.txt")
			case "nested secret":
				path = filepath.Join(wt, ".tmp", ".env")
			}
			write(t, path, "unique local content\n")
			fresh, _, err := h.Inspect(ctx, wt)
			if err != nil || fresh.CanRemoveReviewed {
				t.Fatalf("unsafe row advertised permanent removal: %+v %v", fresh, err)
			}
			for _, reviewed := range []Worktree{row, fresh} {
				if _, err := h.RemoveReviewed(ctx, wt, RemovalReview{Head: reviewed.Head, Reasons: reviewed.Reasons}); err == nil {
					t.Fatal("removed protected local content")
				}
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != "unique local content\n" {
				t.Fatalf("protected content changed: %q %v", got, err)
			}
		})
	}
}

func TestRemoveReviewedRechecksIgnoredSecretsAfterMeasuring(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	wt := f.worktree(t, "late-secret")
	commit(t, wt, "work.txt", "source\n", "source")
	write(t, filepath.Join(wt, ".tmp", "test.log"), "scratch\n")
	h := New(newMemStore(), home, Options{})
	ctx := context.Background()
	row, _, err := h.Inspect(ctx, wt)
	if err != nil || !row.CanRemoveReviewed {
		t.Fatalf("initial row: %+v %v", row, err)
	}
	secret := filepath.Join(wt, ".tmp", ".env")
	progress := &phaseRecorder{onPhase: func(phase string) {
		if phase == PhaseMeasuring {
			write(t, secret, "TOKEN=[REDACTED]\n")
		}
	}}
	_, err = h.remove(ctx, wt, progress, &RemovalReview{Head: row.Head, Reasons: row.Reasons})
	if !errors.Is(err, ErrReviewChanged) || !exists(secret) {
		t.Fatalf("late ignored secret was not preserved: %v", err)
	}
}
