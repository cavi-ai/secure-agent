package store

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// Harness activity reads only the trace index, not the events table.
func TestHarnessActivityUsesTheTraceIndex(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if plan := queryPlan(t, s, harnessActivitySQL, "2026-10-07T00:00:00Z"); !strings.Contains(plan, "COVERING INDEX idx_events_trace_ts") {
		t.Errorf("harness activity plan = %q, want covering idx_events_trace_ts", plan)
	}
}

// Each harness gets its newest hook event and newest trace event since the
// cutoff; older events, other kinds, and sessions without a harness are left
// out.
func TestHarnessActivitySince(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	base := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	for _, sess := range []model.Session{
		{ID: "c1", Harness: "claude", StartedAt: base, LastSeenAt: base},
		{ID: "x1", Harness: "codex", StartedAt: base, LastSeenAt: base},
		{ID: "n1", StartedAt: base, LastSeenAt: base},
	} {
		if err := s.UpsertSession(sess); err != nil {
			t.Fatal(err)
		}
	}
	for i, e := range []event.Event{
		{Kind: event.KindPluginAction, SessionID: "c1", TS: base.Add(-2 * time.Hour)},
		{Kind: event.KindPluginAction, SessionID: "c1", TS: base.Add(10 * time.Minute)},
		{Kind: event.KindToolCall, SessionID: "c1", TS: base.Add(20 * time.Minute), CallID: "t1"},
		{Kind: event.KindTurn, SessionID: "c1", TS: base.Add(30 * time.Minute)},
		{Kind: event.KindFileOpen, SessionID: "c1", TS: base.Add(40 * time.Minute)},
		{Kind: event.KindModelCall, SessionID: "x1", TS: base.Add(5 * time.Minute)},
		{Kind: event.KindModelCall, SessionID: "x1", TS: base.Add(-time.Hour)},
		{Kind: event.KindPluginAction, SessionID: "n1", TS: base.Add(50 * time.Minute)},
	} {
		e.PID = int32(100 + i)
		s.PutEvent(e)
	}
	got := s.HarnessActivitySince(base)
	want := map[string]HarnessActivity{
		"claude": {HookLastSeen: base.Add(10 * time.Minute).Format(time.RFC3339Nano), TraceLastSeen: base.Add(30 * time.Minute).Format(time.RFC3339Nano)},
		"codex":  {TraceLastSeen: base.Add(5 * time.Minute).Format(time.RFC3339Nano)},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("HarnessActivitySince = %v, want %v", got, want)
	}
}

// BenchmarkHarnessActivitySince: 300,000 events over ten days, 18% of them
// hook and trace events across 2,000 sessions, read for the last 24 h (10%
// of the trace events, as in a long-running store).
func BenchmarkHarnessActivitySince(b *testing.B) {
	s, err := Open(filepath.Join(b.TempDir(), "e.db"), "")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { s.Close() })
	tx, err := s.db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	harnesses := []string{"claude", "codex", "cursor", "openclaw"}
	start := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 2000; i++ {
		ts := start.Format(time.RFC3339Nano)
		if _, err := tx.Exec(`INSERT INTO sessions (id, harness, started_at, last_seen_at, status) VALUES (?, ?, ?, ?, 'ended')`,
			fmt.Sprintf("s%d", i), harnesses[i%len(harnesses)], ts, ts); err != nil {
			b.Fatal(err)
		}
	}
	kinds := []event.Kind{event.KindToolCall, event.KindModelCall, event.KindTurn, event.KindPluginAction}
	for i := 0; i < 300000; i++ {
		kind := event.KindFileOpen
		if i%11 < 2 {
			kind = kinds[i%len(kinds)]
		}
		if _, err := tx.Exec(`INSERT INTO events (kind, ts, pid, exe_path, session_id, path) VALUES (?, ?, ?, '/bin/x', ?, '/tmp/f')`,
			int(kind), start.Add(time.Duration(i)*2880*time.Millisecond).Format(time.RFC3339Nano), i%400, fmt.Sprintf("s%d", i%2000)); err != nil {
			b.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	since := start.Add(9 * 24 * time.Hour)
	b.Run("read", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			s.HarnessActivitySince(since)
		}
	})
	// Below the 1,000-insert prune trigger: the cost of one model call row.
	b.Run("insert", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			s.PutEvent(event.Event{Kind: event.KindModelCall, TS: start.Add(240*time.Hour + time.Duration(i)*time.Millisecond),
				PID: int32(i % 400), SessionID: fmt.Sprintf("s%d", i%2000), Model: "m"})
		}
	})
}
