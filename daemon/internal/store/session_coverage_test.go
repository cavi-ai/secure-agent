package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestSessionCoverageSurvivesBriefConnectionContention(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "coverage.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	if err := s.UpsertSession(model.Session{ID: "s", Harness: "claude", RootPID: 42, StartedAt: now.Add(-time.Hour), LastSeenAt: now, Status: model.SessionActive}); err != nil {
		t.Fatal(err)
	}
	s.db.SetMaxOpenConns(1)
	// Occupy the SQLite connection briefly, as another evidence read
	// or write can do while the coverage snapshot is waiting for its turn.
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	type result struct {
		facts []SessionCoverageFact
		err   error
	}
	read := make(chan result, 1)
	go func() {
		facts, err := s.SessionCoverageSince([]int32{42}, now.Add(-time.Hour), now)
		read <- result{facts, err}
	}()
	time.Sleep(150 * time.Millisecond)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-read:
		if got.err != nil || len(got.facts) != 1 || got.facts[0].ID != "s" {
			t.Fatalf("coverage after brief contention: %+v, err=%v", got.facts, got.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("coverage read did not finish after releasing the connection")
	}
}

// Each newest-event lookup seeks idx_events_session_activity; no lookup walks
// a session's events or sorts them.
func TestSessionCoverageQueryUsesSessionActivityIndex(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	q, args := sessionCoverageQuery([]int32{41, 42}, now.Add(-time.Hour), now)
	plan := queryPlan(t, s, q, args...)
	if got := strings.Count(plan, "idx_events_session_activity"); got != 5 {
		t.Fatalf("plan = %q, want five idx_events_session_activity seeks", plan)
	}
	if strings.Contains(plan, "idx_events_session_kind_id") || strings.Contains(plan, "TEMP B-TREE") {
		t.Fatalf("plan = %q, want no session walk or sort", plan)
	}
}

// The newest trace event is chosen by instant across tool calls, turns and
// model calls, including legacy offset timestamps; a newer non-guard plugin
// action does not hide the newest guard answer, and future events are out.
func TestSessionCoverageNewestEventByInstant(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	base := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	if err := s.UpsertSession(model.Session{ID: "s", Harness: "claude", RootPID: 42, StartedAt: base.Add(-time.Hour), LastSeenAt: base, Status: model.SessionActive}); err != nil {
		t.Fatal(err)
	}
	s.PutEvent(event.Event{Kind: event.KindPluginAction, SessionID: "s", TS: base.Add(time.Second), Detail: "secret-guard:deny"})
	s.PutEvent(event.Event{Kind: event.KindPluginAction, SessionID: "s", TS: base.Add(3 * time.Second), Detail: "session-start"})
	s.PutEvent(event.Event{Kind: event.KindTurn, SessionID: "s", TS: base.Add(2 * time.Second)})
	s.PutEvent(event.Event{Kind: event.KindToolCall, SessionID: "s", TS: base.Add(2500 * time.Millisecond), CallID: "a"})
	s.PutEvent(event.Event{Kind: event.KindModelCall, SessionID: "s", TS: base.Add(time.Minute), CallID: "m"})

	facts, err := s.SessionCoverageSince([]int32{42}, base.Add(-time.Hour), base.Add(10*time.Second))
	if err != nil || len(facts) != 1 {
		t.Fatalf("facts = %+v, err = %v", facts, err)
	}
	if facts[0].TraceLastSeen != "2026-10-08T12:00:02.5Z" || facts[0].HookLastSeen != "2026-10-08T12:00:01Z" {
		t.Fatalf("trace = %q, hook = %q", facts[0].TraceLastSeen, facts[0].HookLastSeen)
	}

	if _, err := s.db.Exec(`INSERT INTO events (kind, ts, session_id) VALUES (?, ?, ?)`, int(event.KindTurn), "2026-10-08T08:00:03-04:00", "s"); err != nil {
		t.Fatal(err)
	}
	facts, err = s.SessionCoverageSince([]int32{42}, base.Add(-time.Hour), base.Add(10*time.Second))
	if err != nil || len(facts) != 1 || facts[0].TraceLastSeen != "2026-10-08T08:00:03-04:00" {
		t.Fatalf("legacy offset row: facts = %+v, err = %v", facts, err)
	}
}
