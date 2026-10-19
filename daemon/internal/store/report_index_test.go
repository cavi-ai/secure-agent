package store

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func assertReportEventIndex(t *testing.T, s *Store) {
	t.Helper()
	plan := queryPlan(t, s, sessionEventsSQL, "owned", reportEventCap)
	if !strings.Contains(plan, "SEARCH events USING INDEX idx_events_session_time (session_id=?)") || strings.Contains(plan, "TEMP B-TREE") {
		t.Fatalf("report event plan = %q, want an ordered session seek without a sort", plan)
	}
}

func TestReportEventsUpgradePreservesInstantOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	s, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if s != nil {
			s.Close()
		}
	}()
	for _, row := range []struct{ at, detail string }{
		{"2500-01-01T00:00:00Z", "future"},
		{"2026-10-19T00:00:00.000000200Z", "later"},
		{"2026-10-19T01:00:00.000000100+01:00", "first tie"},
		{"2026-10-19T00:00:00.0000001Z", "second tie"},
		{"2026-10-19T00:00:00Z", "whole second"},
		{"1600-01-01T00:00:00Z", "past"},
	} {
		if _, err := s.db.Exec(`INSERT INTO events(kind,ts,session_id,detail) VALUES (?,?,?,?)`, event.KindFileOpen, row.at, "owned", row.detail); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec(`INSERT INTO events(kind,ts,session_id,detail) VALUES (1,'2000-01-01T00:00:00Z','other','other session'); DROP INDEX IF EXISTS idx_events_session_time`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	assertReportEventIndex(t, s)
	events, err := s.sessionEventsOldestFirst("owned")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range events {
		got = append(got, e.Detail)
	}
	if want := []string{"past", "whole second", "first tie", "second tie", "later", "future"}; !slices.Equal(got, want) {
		t.Fatalf("report event order = %v, want %v", got, want)
	}
}

func TestReportEventDeadlineRetainsFailureAndRecovers(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.db.Exec(`INSERT INTO events(kind,ts,session_id,detail) VALUES (1,'2026-10-19T00:00:00Z','owned','retained')`); err != nil {
		t.Fatal(err)
	}
	// Exhaust the in-memory store's single connection. Waiting for that
	// connection must still consume the report's existing deadline.
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	events, err := s.sessionEventsOldestFirst("owned")
	if !errors.Is(err, context.DeadlineExceeded) || events != nil {
		t.Fatalf("blocked report returned partial evidence: %v, %v", events, err)
	}
	if h := s.WriteHealth(); len(h.ReadIssues) != 1 || h.ReadIssues[0].Category != "deadline" || len(h.ReadActive) != 1 {
		t.Fatalf("report deadline diagnostic = %+v", h)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	events, err = s.sessionEventsOldestFirst("owned")
	if err != nil || len(events) != 1 || events[0].Detail != "retained" {
		t.Fatalf("recovered report = %v, %v", events, err)
	}
	if h := s.WriteHealth(); len(h.ReadActive) != 0 || len(h.ReadIssues) != 1 || h.ReadIssues[0].RecoveredAt == nil {
		t.Fatalf("report recovery diagnostic = %+v", h)
	}
}

func TestReportEventsReadTheOldestEventsAtTheCap(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.db.Exec(`WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<20001)
		INSERT INTO events(kind,ts,session_id,path,remote_host,detail,tool,tool_status,duration_ms,model,tokens_in,tokens_out,cost_usd)
		SELECT 1, '2026-10-19T00:00:00.' || printf('%09d',20001-x) || 'Z', 'owned', '/fixture', 'example.test', 'fixture', 'Read', 'ok', 3, 'model', 7, 2, 0.1 FROM n`); err != nil {
		t.Fatal(err)
	}
	events, err := s.sessionEventsOldestFirst("owned")
	if err != nil || len(events) != 20000 {
		t.Fatalf("capped report read = %d events, %v", len(events), err)
	}
	if first, last := events[0], events[len(events)-1]; first.TS.Nanosecond() != 0 || last.TS.Nanosecond() != 19999 || first.TokensIn != 7 || last.ToolName != "Read" {
		t.Fatalf("report selected the wrong boundary rows: first=%+v last=%+v", first, last)
	}
}
