package store

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A session report reads its events in index order, with no temporary sort,
// so a long session fits the report's read budget.
func TestSessionReportOrderUsesAnIndex(t *testing.T) {
	s := reviewStore(t)
	rows, err := s.db.Query(`EXPLAIN QUERY PLAN `+sessionEventsSQL, "s1", reportEventCap)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	got := strings.Join(plan, "; ")
	if strings.Contains(got, "TEMP B-TREE") || !strings.Contains(got, "idx_events_session_time") {
		t.Fatalf("session report plan: %s", got)
	}
}

// 200k events, half of them one long session's, recorded out of time order;
// its report reads the first reportEventCap.
func BenchmarkSessionEventsOldestFirst(b *testing.B) {
	s, err := Open(filepath.Join(b.TempDir(), "e.db"), "")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { s.Close() })
	tx, err := s.db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 200000; i++ {
		ts := base.Add(time.Duration((i*7919)%200000) * time.Millisecond).Format(time.RFC3339Nano)
		if _, err := tx.Exec(`INSERT INTO events (kind, ts, pid, session_id, path) VALUES (0, ?, 1, ?, '/w/f.go')`,
			ts, sessionOf(i)); err != nil {
			b.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	refreshPlannerStats(s.db)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		events, err := s.sessionEventsOldestFirst("long")
		if err != nil || len(events) != reportEventCap {
			b.Fatalf("%d events, %v", len(events), err)
		}
	}
}

func sessionOf(i int) string {
	if i%2 == 0 {
		return "long"
	}
	return fmt.Sprintf("s%d", i%20)
}
