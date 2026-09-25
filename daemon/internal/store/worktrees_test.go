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
	s.PutCleanup(model.CleanupEntry{TS: now, Action: "trash:tmp", Path: "/r/.tmp", Repo: "/r", Bytes: 4096})
	s.PutCleanup(model.CleanupEntry{TS: now, Action: "ask:none", Path: "/r/.worktrees/new", Repo: "/r", Detail: "claude answered: none"})

	log := s.CleanupLog(10)
	if len(log) != 5 || log[0].Action != "ask:none" || log[1].Action != "trash:tmp" || log[2].Action != "worktree-prune" || log[3].Bytes != 250 || log[3].Detail != "branch feat/new kept" || !log[4].TS.Equal(now.Add(-40*24*time.Hour)) {
		t.Fatalf("log = %+v", log)
	}
	tot := s.CleanupTotals(now)
	if tot.Bytes != 1250 || tot.Count != 3 || tot.Bytes30d != 250 || tot.Count30d != 2 || tot.TrashedBytes != 4096 || tot.TrashedCount != 1 {
		t.Fatalf("totals = %+v (an agent's answer is not a cleanup)", tot)
	}
}

// The daily series covers the requested days ending today in the caller's
// location, zero-filled and oldest first; a cleanup lands on its local
// day, Trash moves sum and count apart (so a day's count agrees with
// CleanupTotals) and an agent's answer is not counted.
func TestCleanupDaily(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	loc := time.FixedZone("UTC-4", -4*3600)
	now := time.Date(2026, 9, 25, 10, 0, 0, 0, loc)
	put := func(at time.Time, action string, bytes int64) {
		s.PutCleanup(model.CleanupEntry{TS: at, Action: action, Path: "/r/x", Repo: "/r", Bytes: bytes})
	}
	put(now.Add(-time.Hour), "worktree-remove", 100)
	put(now.Add(-2*time.Hour), "trash:orphan-worktree", 40)
	put(now.Add(-3*time.Hour), "ask:pr", 0)
	// 01:30 UTC on the 25th is 21:30 on the 24th here.
	put(time.Date(2026, 9, 25, 1, 30, 0, 0, time.UTC), "clean:go", 7)
	put(time.Date(2026, 9, 23, 0, 0, 0, 500000000, loc), "worktree-remove", 3)
	put(time.Date(2026, 9, 22, 23, 59, 59, 0, loc), "worktree-remove", 1000)

	days := s.CleanupDaily(now, 3)
	want := []model.CleanupDay{
		{Day: "2026-09-23", Bytes: 3, Count: 1},
		{Day: "2026-09-24", Bytes: 7, Count: 1},
		{Day: "2026-09-25", Bytes: 100, Count: 1, TrashedBytes: 40, TrashedCount: 1},
	}
	if len(days) != len(want) {
		t.Fatalf("days = %+v", days)
	}
	for i := range want {
		if days[i] != want[i] {
			t.Fatalf("day %d = %+v, want %+v (all: %+v)", i, days[i], want[i], days)
		}
	}
	if got := s.CleanupDaily(now, 0); got != nil {
		t.Fatalf("0 days = %+v", got)
	}
	if got := s.CleanupDaily(now, 10000); len(got) != maxCleanupDays || got[len(got)-1].Day != "2026-09-25" {
		t.Fatalf("capped series: %d days ending %+v", len(got), got[len(got)-1])
	}
}

func TestAgentAsksAndSessionsInWorkspace(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	t0 := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	for _, sess := range []model.Session{
		{ID: "claude-old", Harness: "claude", Workspace: "/r/.worktrees/a", StartedAt: t0, LastSeenAt: t0, Confidence: model.ConfHook},
		{ID: "codex-new", Harness: "codex", Workspace: "/r/.worktrees/a/pkg", StartedAt: t0, LastSeenAt: t0.Add(time.Hour), Confidence: model.ConfTranscript},
		{ID: "proc-1", Harness: "claude", Workspace: "/r/.worktrees/a", StartedAt: t0, LastSeenAt: t0.Add(2 * time.Hour), Confidence: model.ConfProcessTree},
		{ID: "other", Harness: "claude", Workspace: "/r/.worktrees/ab", StartedAt: t0, LastSeenAt: t0, Confidence: model.ConfHook},
		{ID: "wild", Harness: "claude", Workspace: "/r/.worktrees/a_b", StartedAt: t0, LastSeenAt: t0, Confidence: model.ConfHook},
	} {
		s.UpsertSession(sess)
	}
	got := s.SessionsInWorkspace("/r/.worktrees/a")
	if len(got) != 2 || got[0].ID != "codex-new" || got[1].ID != "claude-old" {
		t.Fatalf("sessions = %+v (want the resumable ones under the path, newest first)", got)
	}
	if n := len(s.SessionsInWorkspace("/r/.worktrees/a_")); n != 0 {
		t.Fatalf("an underscore must not act as a LIKE wildcard: %d", n)
	}

	id := s.PutAgentAsk(model.AgentAsk{TS: t0, Path: "/r/.worktrees/a", Repo: "/r", Harness: "claude", SessionID: "claude-old", Status: "running"})
	fin := t0.Add(time.Minute)
	s.FinishAgentAsk(model.AgentAsk{ID: id, Status: "answered", Verdict: "pr", Detail: "https://example.test/pr/1", CostUSD: 0.12, Output: "done", FinishedAt: &fin})
	asks := s.AgentAsks(5)
	if len(asks) != 1 || asks[0].Verdict != "pr" || asks[0].CostUSD != 0.12 || asks[0].FinishedAt == nil || !asks[0].FinishedAt.Equal(fin) || asks[0].SessionID != "claude-old" {
		t.Fatalf("asks = %+v", asks)
	}
}
