package store

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestWorktreeReposUpsertSourceAndHidden(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	t0 := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	s.UpsertWorktreeRepo("/r/a", model.RepoSourceSession, t0)
	s.UpsertWorktreeRepo("/r/b", model.RepoSourceManual, t0)
	// A later scan sighting refreshes last_scan but keeps first_seen and source.
	s.UpsertWorktreeRepo("/r/a", model.RepoSourceScan, t0.Add(time.Hour))

	got := s.WorktreeRepos()
	if len(got) != 2 {
		t.Fatalf("repos = %d, want 2: %+v", len(got), got)
	}
	a := got[0]
	if a.Path != "/r/a" || a.Source != model.RepoSourceSession || !a.FirstSeen.Equal(t0) || !a.LastScan.Equal(t0.Add(time.Hour)) {
		t.Fatalf("repo a = %+v", a)
	}

	if !s.SetWorktreeRepoHidden("/r/a", true) {
		t.Fatal("hide existing repo reported missing")
	}
	if s.SetWorktreeRepoHidden("/r/none", true) {
		t.Fatal("hide unknown repo reported found")
	}
	// A non-manual sighting never unhides.
	s.UpsertWorktreeRepo("/r/a", model.RepoSourceSession, t0.Add(2*time.Hour))
	if got := s.WorktreeRepos(); !got[0].Hidden {
		t.Fatalf("session sighting unhid the repo: %+v", got[0])
	}
	// A manual add unhides and takes over the source.
	s.UpsertWorktreeRepo("/r/a", model.RepoSourceManual, t0.Add(3*time.Hour))
	if got := s.WorktreeRepos(); got[0].Hidden || got[0].Source != model.RepoSourceManual {
		t.Fatalf("manual add did not unhide/claim: %+v", got[0])
	}
}

func TestWorkspaceActivity(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	t0 := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	s.UpsertSession(model.Session{ID: "s1", Harness: "claude", Workspace: "/w/one", StartedAt: t0, LastSeenAt: t0, Status: model.SessionActive})
	s.UpsertSession(model.Session{ID: "s2", Harness: "codex", Workspace: "/w/one", StartedAt: t0, LastSeenAt: t0.Add(time.Hour), Status: model.SessionActive})
	s.EndSession("s2", t0.Add(time.Hour))
	s.EndSession("s1", t0)
	s.UpsertSession(model.Session{ID: "s3", Harness: "claude", Workspace: "/w/two", StartedAt: t0, LastSeenAt: t0, Status: model.SessionIdle})
	s.UpsertSession(model.Session{ID: "s4", Harness: "openclaw", Workspace: "openclaw:main", StartedAt: t0, LastSeenAt: t0})

	got := map[string]model.WorkspaceActivity{}
	for _, a := range s.WorkspaceActivity() {
		got[a.Workspace] = a
	}
	if len(got) != 2 {
		t.Fatalf("workspaces = %+v, want only the two absolute ones", got)
	}
	if one := got["/w/one"]; one.Live || !one.LastSeen.Equal(t0.Add(time.Hour)) {
		t.Fatalf("/w/one = %+v, want ended with newest last_seen", one)
	}
	if two := got["/w/two"]; !two.Live {
		t.Fatalf("/w/two = %+v, want live (idle)", two)
	}
}

func TestCleanupLedger(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	s.PutCleanup(model.CleanupEntry{TS: now.Add(-40 * 24 * time.Hour), Action: "worktree-remove", Path: "/r/.worktrees/old", Repo: "/r", Bytes: 1000})
	s.PutCleanup(model.CleanupEntry{TS: now.Add(-time.Hour), Action: "worktree-remove", Path: "/r/.worktrees/new", Repo: "/r", Bytes: 250, Detail: "branch feat/new kept"})
	s.PutCleanup(model.CleanupEntry{TS: now, Action: "worktree-prune", Path: "/r/.worktrees/gone", Repo: "/r"})

	log := s.CleanupLog(10)
	if len(log) != 3 || log[0].Action != "worktree-prune" || log[1].Bytes != 250 || log[1].Detail != "branch feat/new kept" || !log[2].TS.Equal(now.Add(-40*24*time.Hour)) {
		t.Fatalf("log = %+v", log)
	}
	tot := s.CleanupTotals(now)
	if tot.Bytes != 1250 || tot.Count != 3 || tot.Bytes30d != 250 || tot.Count30d != 2 {
		t.Fatalf("totals = %+v", tot)
	}
}
