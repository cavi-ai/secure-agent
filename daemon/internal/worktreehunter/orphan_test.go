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
		want[canonical(filepath.Dir(main))+"/"+filepath.Base(main)+": "+ErrRepoMissing+"; 1 folder still points to it (listed first below)"] = true
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
	repo, err := h.Reconnect(context.Background(), wt)
	if err != nil || repo != newMain {
		t.Fatalf("Reconnect(wt) = %q, %v", repo, err)
	}
	if ref, _, ok := resolveRepo(wt); !ok || ref.Main != canonical(newMain) {
		t.Fatalf("after reconnect %s resolves to %+v, %v", wt, ref, ok)
	}

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
	if !h.Listed(wt) || h.Listed(lost) || h.Listed("/nowhere") {
		t.Fatal("Listed does not follow the report")
	}
	h.bgWG.Wait()
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
	h.bgWG.Wait()
}
