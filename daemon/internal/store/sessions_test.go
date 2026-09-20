package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
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

// Incident aggregation: one incident per rule+session+subject; repeat flags
// become evidence (count bumps, flag ids accumulate, report_json stays
// current). Resolved incidents never match — a recurrence after resolution
// is a new incident.
func TestIncidentAggregation(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now()
	s.PutIncident(model.IncidentReport{
		ID: "inc-1", FlagID: "f1", PID: 1, Agent: "codex", Timestamp: now,
		Rule: "keychain-access", SessionID: "sess-1", Subject: "login.keychain-db",
		Risk: model.RiskHigh, Summary: "first",
	})

	id, ok := s.FindOpenIncident("keychain-access", "sess-1", "login.keychain-db")
	if !ok || id != "inc-1" {
		t.Fatalf("FindOpenIncident = %q, %v", id, ok)
	}
	// Different subject or session must NOT match.
	if _, ok := s.FindOpenIncident("keychain-access", "sess-1", "other.plist"); ok {
		t.Fatal("wrong subject matched")
	}
	if _, ok := s.FindOpenIncident("keychain-access", "sess-2", "login.keychain-db"); ok {
		t.Fatal("wrong session matched")
	}

	s.AggregateIntoIncident("inc-1", "f2", now.Add(time.Hour))
	s.AggregateIntoIncident("inc-1", "f3", now.Add(2*time.Hour))

	got := s.RecentIncidents(5)
	if len(got) != 1 {
		t.Fatalf("incidents = %d, want 1 aggregated", len(got))
	}
	if got[0].AggregateCount != 3 {
		t.Fatalf("aggregate_count = %d, want 3", got[0].AggregateCount)
	}
	if got[0].LastFlagAt == nil || got[0].LastFlagAt.Unix() != now.Add(2*time.Hour).Unix() {
		t.Fatalf("last_flag_at = %v", got[0].LastFlagAt)
	}

	// Resolved: no longer an aggregation target.
	s.db.Exec(`UPDATE incidents SET status = 'resolved' WHERE id = 'inc-1'`)
	if _, ok := s.FindOpenIncident("keychain-access", "sess-1", "login.keychain-db"); ok {
		t.Fatal("resolved incident must not aggregate")
	}
}

// A tool call is one row keyed by (session_id, call_id): the start inserts,
// the completion updates that row, and a transcript re-read (same start) must
// not duplicate it. This is what stopped 5–10× duplicate rows for one call.
func TestToolCallUpsertsOneRow(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()

	start := event.Event{Kind: event.KindToolCall, TS: now, SessionID: "s1",
		CallID: "toolu_1", ToolName: "Bash", ToolStatus: "running"}
	s.PutEvent(start)
	// Re-read of the same start must not create a second row.
	s.PutEvent(start)
	if n := len(s.RecentEvents(10)); n != 1 {
		t.Fatalf("start re-read produced %d rows, want 1", n)
	}

	// Completion updates the same row: status + duration, still one row.
	done := event.Event{Kind: event.KindToolCall, TS: now.Add(3 * time.Second), SessionID: "s1",
		CallID: "toolu_1", ToolName: "Bash", ToolStatus: "ok", DurationMs: 3000}
	s.PutEvent(done)
	got := s.RecentEvents(10)
	if len(got) != 1 {
		t.Fatalf("after completion rows = %d, want 1", len(got))
	}
	if got[0].ToolStatus != "ok" || got[0].DurationMs != 3000 {
		t.Fatalf("row = %+v, want ok/3000", got[0])
	}

	// A different call id is its own row.
	s.PutEvent(event.Event{Kind: event.KindToolCall, TS: now, SessionID: "s1",
		CallID: "toolu_2", ToolName: "Read", ToolStatus: "running"})
	if n := len(s.RecentEvents(10)); n != 2 {
		t.Fatalf("distinct call rows = %d, want 2", n)
	}

	// Non-tool events (no call id) still append freely.
	s.PutEvent(event.Event{Kind: event.KindFileOpen, TS: now, SessionID: "s1", Path: "/x"})
	s.PutEvent(event.Event{Kind: event.KindFileOpen, TS: now, SessionID: "s1", Path: "/x"})
	if n := len(s.RecentEvents(10)); n != 4 {
		t.Fatalf("non-tool rows = %d, want 4 (append, not upsert)", n)
	}
}

// A harness-less upsert must not erase a session's harness. Trace events
// resolve without a pid, so they arrive with Harness == ""; the conflict
// clause used to write excluded.harness unconditionally, stripping the name
// off every transcript-joined session.
func TestUpsertSessionPreservesHarness(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	st.UpsertSession(model.Session{ID: "s1", Harness: "claude", Workspace: "/repo",
		StartedAt: time.Now(), LastSeenAt: time.Now(), Status: model.SessionActive})
	// A later, identity-poor upsert (the trace-event shape).
	st.UpsertSession(model.Session{ID: "s1",
		StartedAt: time.Now(), LastSeenAt: time.Now(), Status: model.SessionActive})

	got, ok := st.GetSession("s1")
	if !ok {
		t.Fatal("session disappeared")
	}
	if got.Harness != "claude" || got.Workspace != "/repo" {
		t.Fatalf("harness clobbered: %+v", got)
	}
}

// An older database (events without call_id) must OPEN — the call index has to
// be created after the column migration, not inside the initial schema batch.
// Regression: "SQL logic error: no such column: call_id" on daemon start.
func TestOpenMigratesOldEventsTableForCallIndex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old.db")
	// Hand-build a pre-trace events table.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, kind INT, ts TEXT, pid INT, exe_path TEXT, session_id TEXT, path TEXT, remote_host TEXT, remote_port INT, detail TEXT)`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	st, err := Open(path, "")
	if err != nil {
		t.Fatalf("Open on an old DB failed: %v", err)
	}
	defer st.Close()
	// And the upsert works end to end on the migrated table.
	st.PutEvent(event.Event{Kind: event.KindToolCall, TS: time.Now(), SessionID: "s", CallID: "c1", ToolStatus: "running"})
	st.PutEvent(event.Event{Kind: event.KindToolCall, TS: time.Now(), SessionID: "s", CallID: "c1", ToolStatus: "ok"})
	if n := len(st.QueryEvents(EventFilter{})); n != 1 {
		t.Fatalf("events=%d want 1 after upsert on migrated table", n)
	}
}

// The default view (Status "") returns live sessions first plus a bounded
// recent-ended tail — a flood of ended stubs must not bury live work or
// fill the whole limit.
func TestDefaultSessionViewLiveFirst(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now()
	for i := 0; i < 40; i++ {
		s.UpsertSession(model.Session{
			ID: fmt.Sprintf("ended-%d", i), Harness: "codex",
			StartedAt: now, LastSeenAt: now, Status: model.SessionEnded,
		})
	}
	for i := 0; i < 3; i++ {
		s.UpsertSession(model.Session{
			ID: fmt.Sprintf("live-%d", i), Harness: "claude",
			StartedAt: now, LastSeenAt: now, Status: model.SessionActive,
		})
	}

	got := s.ListSessions(SessionFilter{Limit: 20})
	live := 0
	ended := 0
	for _, sess := range got {
		if sess.Status == model.SessionEnded {
			ended++
		} else {
			live++
		}
	}
	if live != 3 || ended != 17 {
		t.Fatalf("default view live=%d ended=%d, want 3 live then 17 ended tail", live, ended)
	}
	// Live rows come first.
	if got[0].Status != model.SessionActive {
		t.Fatalf("first row status = %s, want active", got[0].Status)
	}
	// Explicit ended filter still reaches the whole population.
	if n := len(s.ListSessions(SessionFilter{Status: model.SessionEnded, Limit: 100})); n != 40 {
		t.Fatalf("ended filter = %d, want 40", n)
	}
}

// Ending a session closes its stuck "running" tool calls as errors — the
// sweep the trace pairing needed (36 rows ran over an hour past session end).
func TestEndSessionClosesRunningToolCalls(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	s.UpsertSession(model.Session{ID: "sx", RootPID: 7, StartedAt: now, LastSeenAt: now, Status: model.SessionActive})
	s.PutEvent(event.Event{Kind: event.KindToolCall, TS: now, SessionID: "sx", CallID: "c1", ToolName: "Bash", ToolStatus: "running"})
	s.PutEvent(event.Event{Kind: event.KindToolCall, TS: now, SessionID: "sx", CallID: "c2", ToolName: "Read", ToolStatus: "ok"})

	s.EndSession("sx", now.Add(time.Minute))
	kind := int(event.KindToolCall)
	calls := s.QueryEvents(EventFilter{Kind: &kind})
	byID := map[string]string{}
	for _, e := range calls {
		byID[e.CallID] = e.ToolStatus
	}
	if byID["c1"] != "error" {
		t.Fatalf("running call after session end = %q, want error", byID["c1"])
	}
	if byID["c2"] != "ok" {
		t.Fatalf("completed call must stay ok, got %q", byID["c2"])
	}
}
