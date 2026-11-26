package worktreehunter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestResolveRepoRejectsInvalidGitMetadata(t *testing.T) {
	dir := t.TempDir()
	worktree := filepath.Join(dir, "worktree")
	if err := os.Mkdir(worktree, 0700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "not-a-directory"), "fixture")
	for _, pointer := range []string{"gitdir: \n", "gitdir: ../not-a-directory\n", "gitdir: ../not-a-directory/child\n"} {
		write(t, filepath.Join(worktree, ".git"), pointer)
		if ref, orphan, ok := resolveRepo(worktree); ok || orphan != nil {
			t.Errorf("resolveRepo(%q) = %+v, %+v, %v", pointer, ref, orphan, ok)
		}
	}

	bare := filepath.Join(dir, "incomplete.git")
	if err := os.Mkdir(bare, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"HEAD", "objects", "refs"} {
		write(t, filepath.Join(bare, name), "fixture")
	}
	if ref, orphan, ok := resolveRepo(bare); ok || orphan != nil {
		t.Errorf("invalid bare repo resolved as %+v, %+v, %v", ref, orphan, ok)
	}
}

func TestResolveBareRepoWithLegacyHEAD(t *testing.T) {
	isolateGit(t)
	dir := canonical(t.TempDir())
	bare := filepath.Join(dir, "repo.git")
	run(t, dir, "init", "--bare", "--initial-branch=main", bare)
	head := filepath.Join(bare, "HEAD")
	if err := os.Remove(head); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("refs/heads/main", head); err != nil {
		t.Fatal(err)
	}
	if ref, orphan, ok := resolveRepo(bare); !ok || orphan != nil || !ref.Bare || ref.Common != bare {
		t.Fatalf("repository with a symbolic HEAD resolved as %+v, %+v, %v", ref, orphan, ok)
	}
}

func TestResolveRepoWithExternalObjectDirectory(t *testing.T) {
	isolateGit(t)
	dir := canonical(t.TempDir())
	repo := filepath.Join(dir, "repo")
	run(t, dir, "init", "--initial-branch=main", repo)
	commit(t, repo, "file", "contents\n", "initial commit")
	gitDir := filepath.Join(repo, ".git")
	objects := filepath.Join(gitDir, "objects")
	external := filepath.Join(dir, "objects")
	if err := os.Rename(objects, external); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, objects); err != nil {
		t.Fatal(err)
	}
	if got := run(t, repo, "cat-file", "-t", "HEAD"); got != "commit" {
		t.Fatalf("git cat-file -t HEAD = %q, want commit", got)
	}
	if ref, orphan, ok := resolveRepo(repo); !ok || orphan != nil || ref != (repoRef{Common: gitDir, Main: repo}) {
		t.Fatalf("resolveRepo(%q) = %+v, %+v, %v", repo, ref, orphan, ok)
	}
}

// A repository that moved leaves its worktrees pointing at the old path:
// the report groups them under the missing path, names the moved
// repository as the reconnect candidate, and Reconnect links them again.
// A repository that was deleted leaves folders nothing can reconnect;
// TrashOrphan moves them to the Trash and the group and its error go.
func TestOrphansOfMovedAndDeletedRepositories(t *testing.T) {
	home := isolateGit(t)
	moved := newFixture(t)
	wt := filepath.Join(moved.root, "agents", "wip")
	run(t, moved.main, "worktree", "add", "-q", "-b", "feat/wip", wt, "main")
	newMain := moved.main + "-moved"
	if err := os.Rename(moved.main, newMain); err != nil {
		t.Fatal(err)
	}
	deleted := newFixture(t)
	lost := filepath.Join(deleted.root, "agents", "lost")
	run(t, deleted.main, "worktree", "add", "-q", "-b", "feat/lost", lost, "main")
	write(t, filepath.Join(lost, "notes.txt"), "only copy\n")
	if err := os.RemoveAll(deleted.main); err != nil {
		t.Fatal(err)
	}

	st := newMemStore()
	st.activity = []model.WorkspaceActivity{{Workspace: newMain}, {Workspace: wt}, {Workspace: lost}}
	h := New(st, home, Options{})
	h.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	h.goos = "darwin" // the macOS Trash layout; the freedesktop one is the trash package's
	rep := h.Report(context.Background(), true)

	w := findRow(t, rep, wt)
	if !w.Orphan || w.Reconnect != newMain || !strings.Contains(strings.Join(w.Reasons, ";"), "Reconnect links it again") {
		t.Fatalf("moved repo orphan = %+v", w)
	}
	if n := len(w.ReasonKinds); n != len(w.Reasons) || w.ReasonKinds[n-1] != ReasonInfo {
		t.Fatalf("moved repo orphan kinds %q for reasons %q, want one each ending in info", w.ReasonKinds, w.Reasons)
	}
	l := findRow(t, rep, lost)
	if !l.Orphan || l.Reconnect != "" {
		t.Fatalf("deleted repo orphan = %+v", l)
	}
	var lines []string
	for _, e := range rep.Errors {
		if strings.Contains(e, ErrRepoMissing) {
			lines = append(lines, e)
		}
	}
	want := map[string]bool{}
	for _, main := range []string{moved.main, deleted.main} {
		want[canonical(filepath.Dir(main))+"/"+filepath.Base(main)+": "+ErrRepoMissing+"; 1 folder still points to it"] = true
	}
	if len(lines) != 2 || !want[lines[0]] || !want[lines[1]] {
		t.Fatalf("error lines = %q, want %v", lines, want)
	}

	if _, err := h.Reconnect(context.Background(), lost); !errors.Is(err, ErrNoReconnect) {
		t.Fatalf("Reconnect(lost) = %v, want ErrNoReconnect", err)
	}
	if _, err := h.Reconnect(context.Background(), newMain); !errors.Is(err, ErrNotOrphan) {
		t.Fatalf("Reconnect(main) = %v, want ErrNotOrphan", err)
	}
	h.Wait()
	now := h.now
	h = New(st, home, Options{})
	h.now, h.goos = now, "darwin"
	repo, err := h.Reconnect(context.Background(), wt)
	if err != nil || repo != newMain {
		t.Fatalf("Reconnect(wt) = %q, %v", repo, err)
	}
	if ref, _, ok := resolveRepo(wt); !ok || ref.Main != canonical(newMain) {
		t.Fatalf("after reconnect %s resolves to %+v, %v", wt, ref, ok)
	}
	restarted := New(st, home, Options{})
	restarted.now = now
	if row := findRow(t, restarted.Report(t.Context(), false), wt); row.Orphan {
		t.Fatalf("saved scan still shows the reconnected worktree as orphaned: %+v", row)
	}
	restarted.Wait()

	if _, err := h.TrashOrphan(context.Background(), newMain); !errors.Is(err, ErrNotOrphan) {
		t.Fatalf("TrashOrphan(main) = %v, want ErrNotOrphan", err)
	}
	got, err := h.TrashOrphan(context.Background(), lost)
	if err != nil || exists(lost) || !exists(got.TrashPath) || got.Bytes <= 0 {
		t.Fatalf("TrashOrphan(lost) = %+v, %v; still there %v", got, err, exists(lost))
	}
	if !strings.HasPrefix(got.TrashPath, filepath.Join(home, ".Trash")) {
		t.Fatalf("trash path %s is not under the home Trash", got.TrashPath)
	}
	if n := len(st.cleanup); n != 1 || st.cleanup[0].Action != "trash:orphan-worktree" || st.cleanup[0].Bytes != got.Bytes {
		t.Fatalf("ledger = %+v", st.cleanup)
	}
	after := h.Report(context.Background(), false)
	for _, r := range after.Repos {
		if r.Path == canonical(deleted.main) {
			t.Fatalf("the emptied missing-repo group stayed: %+v", r)
		}
	}
	for _, e := range after.Errors {
		if strings.HasPrefix(e, canonical(deleted.main)+": ") {
			t.Fatalf("its error line stayed: %q", e)
		}
	}
	if h.ListedPath(wt) != wt || h.ListedPath(lost) != "" || h.ListedPath("/nowhere") != "" {
		t.Fatal("Listed does not follow the report")
	}
	h.Wait()
}

func TestSavedOrphanCountAfterTrash(t *testing.T) {
	home := isolateGit(t)
	f := newFixture(t)
	one, two := filepath.Join(f.root, "one"), filepath.Join(f.root, "two")
	run(t, f.main, "worktree", "add", "-q", "-b", "feat/one", one, "main")
	run(t, f.main, "worktree", "add", "-q", "-b", "feat/two", two, "main")
	if err := os.RemoveAll(f.main); err != nil {
		t.Fatal(err)
	}
	st := newMemStore()
	st.activity = []model.WorkspaceActivity{{Workspace: one}, {Workspace: two}}
	h := New(st, home, Options{})
	h.goos = "darwin"
	before := h.Report(t.Context(), false)
	h.Wait()
	if len(before.Errors) != 1 || !strings.Contains(before.Errors[0], "2 folders still point") {
		t.Fatalf("initial errors = %q", before.Errors)
	}
	if _, err := h.TrashOrphan(t.Context(), one); err != nil {
		t.Fatal(err)
	}
	restarted := New(st, home, Options{})
	after := restarted.Report(t.Context(), false)
	restarted.Wait()
	if !after.Cached || len(after.Errors) != 1 || !strings.Contains(after.Errors[0], "1 folder still points") {
		t.Fatalf("saved report after trash: cached=%v, errors=%q", after.Cached, after.Errors)
	}
}

// agentAt reads every session at or under a folder: in use when any is
// active, named by a live session before a newer ended one, and the newest
// last_seen of all of them.
func TestAgentAt(t *testing.T) {
	now := time.Date(2026, 10, 12, 19, 0, 0, 0, time.UTC)
	activity := []model.WorkspaceActivity{
		{Workspace: "/r/.worktrees/x", Harness: "claude", Live: true, LastSeen: now.Add(-3 * time.Hour)},
		{Workspace: "/r/.worktrees/x/sub", Harness: "codex", LastSeen: now.Add(-time.Minute)},
		{Workspace: "/r/.worktrees/xy", Harness: "cursor", Live: true, LastSeen: now},
		{Workspace: "/r/.worktrees/old", Harness: "codex", LastSeen: now.Add(-time.Hour)},
	}
	if in, agent, seen := agentAt("/r/.worktrees/x", activity, now); !in || agent != "claude" || !seen.Equal(now.Add(-time.Minute)) {
		t.Fatalf("x: in=%v agent=%q seen=%v, want in use, claude (live), newest last_seen", in, agent, seen)
	}
	if in, agent, _ := agentAt("/r/.worktrees/old", activity, now); in || agent != "" {
		t.Fatalf("old: in=%v agent=%q, want not in use", in, agent)
	}
}

// An orphan folder an agent is working in is kept, names the agent, and
// refuses the move to the Trash.
func TestTrashOrphanRefusesAnAgentWorkingThere(t *testing.T) {
	home := isolateGit(t)
	deleted := newFixture(t)
	lost := filepath.Join(deleted.root, "agents", "lost")
	run(t, deleted.main, "worktree", "add", "-q", "-b", "feat/lost", lost, "main")
	write(t, filepath.Join(lost, "notes.txt"), "only copy\n")
	if err := os.RemoveAll(deleted.main); err != nil {
		t.Fatal(err)
	}
	st := newMemStore()
	h := New(st, home, Options{})
	now := time.Now()
	h.now = func() time.Time { return now }
	h.goos = "darwin"
	// Ended an hour ago by its status, still seen two minutes ago.
	st.activity = []model.WorkspaceActivity{{Workspace: filepath.Join(lost, "src"), Harness: "codex", LastSeen: now.Add(-2 * time.Minute)}}
	row := findRow(t, h.Report(context.Background(), true), lost)
	if !row.Orphan || !row.InUse || row.ActiveAgent != "codex" || row.State != StateKeep || !slices.Contains(row.Reasons, "codex is working here") {
		t.Fatalf("orphan row = %+v, want a kept orphan naming codex", row)
	}
	_, err := h.TrashOrphan(context.Background(), lost)
	var refused *NotReviewableError
	if !errors.As(err, &refused) || refused.Why != "codex is working here" {
		t.Fatalf("TrashOrphan = %v, want refused: codex is working here", err)
	}
	if _, err := os.Stat(filepath.Join(lost, "notes.txt")); err != nil {
		t.Fatalf("the refused folder moved: %v", err)
	}
	h.Wait()
}
