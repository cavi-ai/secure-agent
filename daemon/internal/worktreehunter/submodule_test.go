package worktreehunter

import (
	"context"
	"errors"
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
