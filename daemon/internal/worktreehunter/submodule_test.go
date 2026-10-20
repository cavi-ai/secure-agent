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

// git refuses to remove a worktree with populated submodules unless
// forced. A clean one, every submodule commit on a remote, is removed; a
// submodule branch commit or stash that lives only in the worktree's own
// git dir keeps it, since removal deletes that dir.
func TestWorktreesWithSubmodules(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	allow := []string{"-c", "protocol.file.allow=always"}
	subOrigin := filepath.Join(f.root, "sub.git")
	run(t, f.root, "init", "-q", "--bare", "-b", "main", subOrigin)
	seed := filepath.Join(f.root, "sub-seed")
	run(t, f.root, "clone", "-q", subOrigin, seed)
	run(t, seed, "checkout", "-q", "-b", "main")
	commit(t, seed, "lib.txt", "v1\n", "lib v1")
	run(t, seed, "push", "-q", "-u", "origin", "main")
	run(t, f.main, append(allow, "submodule", "add", "-q", subOrigin, "lib")...)
	run(t, f.main, "commit", "-q", "-m", "add lib")
	run(t, f.main, "push", "-q", "origin", "main")

	withSub := func(name string) string {
		wt := f.worktree(t, name)
		run(t, wt, append(allow, "submodule", "update", "-q", "--init")...)
		return wt
	}
	clean := withSub("clean")
	local := withSub("local")
	lib := filepath.Join(local, "lib")
	recorded := run(t, lib, "rev-parse", "HEAD")
	run(t, lib, "checkout", "-q", "-b", "experiment")
	commit(t, lib, "idea.txt", "idea\n", "local only")
	run(t, lib, "checkout", "-q", recorded)
	stashed := withSub("stashed")
	write(t, filepath.Join(stashed, "lib", "lib.txt"), "wip\n")
	run(t, filepath.Join(stashed, "lib"), "stash", "-q")

	st := newMemStore()
	st.activity = []model.WorkspaceActivity{{Workspace: f.main}}
	h := New(st, home, Options{})
	h.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	rep := h.Report(context.Background(), true)

	c := findRow(t, rep, clean)
	if c.State != StateRemove || c.Submodules != 1 || !strings.Contains(strings.Join(c.Reasons, ";"), "1 submodule with every commit on a remote") {
		t.Fatalf("clean = %s %d %v", c.State, c.Submodules, c.Reasons)
	}
	l := findRow(t, rep, local)
	if l.State != StateKeep || !strings.Contains(strings.Join(l.Reasons, ";"), "submodule lib has 1 commit on no remote (removal loses them)") {
		t.Fatalf("local = %s %v", l.State, l.Reasons)
	}
	s := findRow(t, rep, stashed)
	if s.State != StateKeep || !strings.Contains(strings.Join(s.Reasons, ";"), "submodule lib has a stash (removal loses it)") {
		t.Fatalf("stashed = %s %v", s.State, s.Reasons)
	}

	var refused *NotRemovableError
	if _, err := h.Remove(context.Background(), local); !errors.As(err, &refused) || !exists(lib) {
		t.Fatalf("Remove(local) = %v; lib still there %v", err, exists(lib))
	}
	if _, err := h.Remove(context.Background(), clean); err != nil || exists(clean) {
		t.Fatalf("Remove(clean) = %v; still there %v", err, exists(clean))
	}
	if strings.Contains(run(t, f.main, "worktree", "list", "--porcelain"), clean) {
		t.Fatal("git still lists the removed worktree")
	}
	h.bgWG.Wait()
}

func TestReviewedSubmoduleRemoval(t *testing.T) {
	for _, kind := range []string{"temporary files", "local commit", "stash", "partly staged", "operation"} {
		t.Run(kind, func(t *testing.T) {
			home := isolateGit(t)
			f := newFixture(t)
			origin := filepath.Join(f.root, "sub.git")
			run(t, f.root, "init", "-q", "--bare", "-b", "main", origin)
			seed := filepath.Join(f.root, "seed")
			run(t, f.root, "clone", "-q", origin, seed)
			commit(t, seed, "lib.txt", "original\n", "initial")
			run(t, seed, "push", "-q", "origin", "HEAD:main")
			allow := []string{"-c", "protocol.file.allow=always"}
			run(t, f.main, append(allow, "submodule", "add", "-q", origin, "lib")...)
			run(t, f.main, "commit", "-q", "-m", "add submodule")
			run(t, f.main, "push", "-q", "origin", "main")
			wt := f.worktree(t, "review-submodule")
			run(t, wt, append(allow, "submodule", "update", "-q", "--init", "--recursive")...)
			sub := filepath.Join(wt, "lib")
			write(t, filepath.Join(wt, "scratch.tmp"), "disposable\n")
			switch kind {
			case "local commit":
				commit(t, sub, "local.txt", "local work\n", "local")
			case "stash":
				write(t, filepath.Join(sub, "lib.txt"), "stashed\n")
				run(t, sub, "stash", "-q")
			case "partly staged":
				write(t, filepath.Join(sub, "lib.txt"), "staged\n")
				run(t, sub, "add", "lib.txt")
				write(t, filepath.Join(sub, "lib.txt"), "working copy\n")
			case "operation":
				admin := run(t, sub, "rev-parse", "--absolute-git-dir")
				write(t, filepath.Join(admin, "MERGE_HEAD"), run(t, sub, "rev-parse", "HEAD")+"\n")
			}
			h := New(newMemStore(), home, Options{})
			h.goos = "darwin"
			ctx := context.Background()
			row, _, err := h.Inspect(ctx, wt)
			if err != nil || row.Submodules != 1 {
				t.Fatalf("inspection: %+v, %v", row, err)
			}
			result, err := h.TrashReviewed(ctx, wt, row.Head, row.Reasons)
			if kind != "temporary files" {
				var refused *NotReviewableError
				if !errors.As(err, &refused) || !strings.Contains(refused.Why, "submodule lib") || !exists(wt) {
					t.Fatalf("protected submodule: result=%+v error=%v", result, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("reviewed worktree with clean submodule: %v", err)
			}
			for _, path := range []string{"scratch.tmp", "lib/lib.txt"} {
				if _, err := os.Stat(filepath.Join(result.TrashPath, path)); err != nil {
					t.Fatalf("reviewed contents not preserved: %s: %v", path, err)
				}
			}
			if exists(wt) || strings.Contains(run(t, f.main, "worktree", "list", "--porcelain"), wt) {
				t.Fatal("reviewed worktree was not removed from git")
			}
		})
	}
}

func TestReviewedNestedSubmoduleRemoval(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	allow := []string{"-c", "protocol.file.allow=always"}
	remote := func(name string) (string, string) {
		origin, seed := filepath.Join(f.root, name+".git"), filepath.Join(f.root, name+"-seed")
		run(t, f.root, "init", "-q", "--bare", "-b", "main", origin)
		run(t, f.root, "clone", "-q", origin, seed)
		commit(t, seed, "file.txt", "original\n", "initial")
		run(t, seed, "push", "-q", "origin", "HEAD:main")
		return origin, seed
	}
	nestedOrigin, _ := remote("nested")
	parentOrigin, parentSeed := remote("parent")
	run(t, parentSeed, append(allow, "submodule", "add", "-q", nestedOrigin, "nested")...)
	run(t, parentSeed, "commit", "-q", "-m", "add nested module")
	run(t, parentSeed, "push", "-q", "origin", "HEAD:main")
	run(t, f.main, append(allow, "submodule", "add", "-q", parentOrigin, "lib")...)
	run(t, f.main, "commit", "-q", "-m", "add parent module")
	run(t, f.main, "push", "-q", "origin", "main")
	wt := f.worktree(t, "nested-review")
	run(t, wt, append(allow, "submodule", "update", "-q", "--init", "--recursive")...)
	write(t, filepath.Join(wt, "scratch.tmp"), "disposable\n")
	h := New(newMemStore(), home, Options{})
	h.goos = "darwin"
	ctx := context.Background()
	row, _, err := h.Inspect(ctx, wt)
	if err != nil || row.Submodules != 2 || len(row.SubmoduleLocal) != 0 {
		t.Fatalf("nested inspection: %+v, %v", row, err)
	}
	nested := filepath.Join(wt, "lib", "nested")
	commit(t, nested, "local.txt", "nested work\n", "nested local work")
	var refused *NotReviewableError
	if _, err := h.TrashReviewed(ctx, wt, row.Head, row.Reasons); !errors.As(err, &refused) || !strings.Contains(refused.Why, "submodule lib/nested") || !exists(nested) {
		t.Fatalf("new nested commit must block stale approval: %v", err)
	}
	run(t, nested, "push", "-q", "origin", "HEAD:main")
	row, _, err = h.Inspect(ctx, wt)
	if err != nil || len(row.SubmoduleLocal) != 0 {
		t.Fatalf("published fixture commit: %+v, %v", row, err)
	}
	result, err := h.TrashReviewed(ctx, wt, row.Head, row.Reasons)
	if err != nil || !exists(filepath.Join(result.TrashPath, "lib", "nested", "local.txt")) || exists(wt) {
		t.Fatalf("nested contents not preserved: %+v, %v", result, err)
	}
}
