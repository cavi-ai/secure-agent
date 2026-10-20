package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/testutil"
)

func TestFileBatchCommitsRowsAndRollupsTogether(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "events.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	at := time.Now().UTC()
	events := []event.Event{
		{Kind: event.KindFileOpen, TS: at, PID: 42, SessionID: "s", Path: "/work/a", Detail: "read"},
		{Kind: event.KindFileWrite, TS: at.Add(time.Second), PID: 42, SessionID: "s", Path: "/work/b"},
	}
	result, err := s.PutFileEvents(events)
	if err != nil || !result.Changed {
		t.Fatalf("batch result=%+v, error=%v", result, err)
	}
	got := testutil.Read[[]event.Event](t)(s.QueryEvents(EventFilter{Limit: 10}))
	if len(got) != 2 {
		t.Fatalf("stored %d events, want 2", len(got))
	}
	var rows, rollups int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE session_id='s' AND pid=42`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT SUM(count) FROM rollup_hourly WHERE kind LIKE 'event:%'`).Scan(&rollups); err != nil {
		t.Fatal(err)
	}
	if rows != 2 || rollups != 2 {
		t.Fatalf("rows=%d rollups=%d", rows, rollups)
	}
	if got[1].Path != "/work/a" || got[1].Detail != "read" {
		t.Fatalf("metadata lost: %+v", got[1])
	}
}

func TestFileBatchRollsBackRowsAndRollupsOnFailure(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "events.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.db.Exec(`CREATE TRIGGER reject_file BEFORE INSERT ON events WHEN NEW.path='/work/reject' BEGIN SELECT RAISE(ABORT,'write rejected'); END`); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	result, err := s.PutFileEvents([]event.Event{
		{Kind: event.KindFileOpen, TS: at, PID: 42, Path: "/work/a"},
		{Kind: event.KindFileOpen, TS: at, PID: 42, Path: "/work/reject"},
	})
	if err == nil || result.Changed {
		t.Fatalf("failed batch reported stored: %+v, %v", result, err)
	}
	var rows, rollups int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM rollup_hourly`).Scan(&rollups); err != nil {
		t.Fatal(err)
	}
	if rows != 0 || rollups != 0 {
		t.Fatalf("partial commit: events=%d rollups=%d", rows, rollups)
	}
	if len(s.WriteHealth().Active) == 0 {
		t.Fatal("failed batch did not degrade storage health")
	}
}
