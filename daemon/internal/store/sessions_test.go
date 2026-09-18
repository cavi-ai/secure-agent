package store

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestSessionLifecycle(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now()
	s.UpsertSession(model.Session{
		ID: "s1", Harness: "claude", Workspace: "/repo", Repo: "repo", Branch: "main",
		RootPID: 100, StartedAt: now, LastSeenAt: now, Status: model.SessionActive, Confidence: model.ConfHook,
	})

	// Upsert with weaker confidence and empty metadata must not downgrade or
	// erase the hook-provided fields.
	s.UpsertSession(model.Session{ID: "s1", Harness: "claude", LastSeenAt: now, Confidence: model.ConfProcessTree})
	got := s.ListSessions(SessionFilter{})
	if len(got) != 1 {
		t.Fatalf("sessions = %d, want 1", len(got))
	}
	if got[0].Repo != "repo" || got[0].Branch != "main" || got[0].Confidence != model.ConfHook {
		t.Fatalf("upsert downgraded/erased metadata: %+v", got[0])
	}

	// Touch reactivates an idle session but never reopens an ended one.
	s.MarkSessionsIdle(now.Add(-time.Hour)) // cutoff in past: no-op for fresh
	if n := len(s.ListSessions(SessionFilter{Status: model.SessionIdle})); n != 0 {
		t.Fatal("fresh session must not be idle")
	}
	s.MarkSessionsIdle(now.Add(time.Hour)) // everything older than cutoff+1h
	if n := len(s.ListSessions(SessionFilter{Status: model.SessionIdle})); n != 1 {
		t.Fatalf("idle sessions = %d, want 1", n)
	}
	s.TouchSession("s1", now.Add(2*time.Hour))
	if n := len(s.ListSessions(SessionFilter{Status: model.SessionActive})); n != 1 {
		t.Fatalf("active sessions = %d, want 1 after touch", n)
	}

	s.EndSession("s1", now.Add(3*time.Hour))
	ended := s.ListSessions(SessionFilter{Status: model.SessionEnded})
	if len(ended) != 1 || ended[0].EndedAt == nil {
		t.Fatalf("ended = %+v, want 1 with ended_at", ended)
	}
	s.TouchSession("s1", now.Add(4*time.Hour))
	if n := len(s.ListSessions(SessionFilter{Status: model.SessionEnded})); n != 1 {
		t.Fatal("touch must not reopen an ended session")
	}
}

func TestRekeySessionRepointsEventsAndFlags(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now()
	s.UpsertSession(model.Session{ID: "proc-100-1", Harness: "claude", RootPID: 100,
		StartedAt: now, LastSeenAt: now, Status: model.SessionActive, Confidence: model.ConfProcessTree})
	s.PutEvent(event.Event{Kind: event.KindExec, PID: 100, TS: now, SessionID: "proc-100-1"})
	s.PutFlag(model.Flag{ID: "f1", Rule: "keychain-access", Severity: 2, TS: now, SessionID: "proc-100-1"})

	s.RekeySession("proc-100-1", "hook-abc")

	if n := len(s.ListSessions(SessionFilter{})); n != 1 {
		t.Fatalf("sessions = %d, want 1 after rekey", n)
	}
	if got := s.ListSessions(SessionFilter{})[0]; got.ID != "hook-abc" {
		t.Fatalf("session id = %q, want hook-abc", got.ID)
	}
	for _, e := range s.RecentEvents(10) {
		if e.SessionID != "hook-abc" {
			t.Fatalf("event session_id = %q, want hook-abc", e.SessionID)
		}
	}
	for _, f := range s.RecentFlags(10) {
		if f.SessionID != "hook-abc" {
			t.Fatalf("flag session_id = %q, want hook-abc", f.SessionID)
		}
	}
}

func TestSessionRootsExcludesEnded(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	s.UpsertSession(model.Session{ID: "live", RootPID: 1, StartedAt: now, LastSeenAt: now, Status: model.SessionActive, Confidence: model.ConfHook})
	s.UpsertSession(model.Session{ID: "dead", RootPID: 2, StartedAt: now, LastSeenAt: now, Status: model.SessionActive, Confidence: model.ConfHook})
	s.EndSession("dead", now)
	roots := s.SessionRoots()
	if _, ok := roots[1]; !ok {
		t.Fatal("live root missing")
	}
	if _, ok := roots[2]; ok {
		t.Fatal("ended session's root must not be reported live")
	}
}
