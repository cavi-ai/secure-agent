package store

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestGuardDecisionStorePersistsRedactedRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard.db")
	s, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	s.PutGuardDecisionForTest(GuardDecision{ID: "d1", SessionID: "s1", RuleID: "cloud-creds", Verdict: "deny", Scope: "once", At: time.Now().UTC().Format(time.RFC3339Nano)})
	s.Close()
	s, err = Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rows := s.ListGuardDecisions("s1", 10)
	if len(rows) != 1 || rows[0].ID != "d1" || rows[0].RuleID != "cloud-creds" {
		t.Fatalf("rows=%+v", rows)
	}
	if got := s.ListGuardDecisions("other", 10); len(got) != 0 {
		t.Fatalf("cross-session rows=%+v", got)
	}
}

func TestGuardDecisionOrderingAndLimit(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// RFC3339Nano strings of unequal precision sort incorrectly as text.
	second := time.Now().UTC().Truncate(time.Second).Format("2006-01-02T15:04:05")
	s.PutGuardDecisionForTest(GuardDecision{ID: "older", SessionID: "s1", RuleID: "r", Verdict: "deny", Scope: "once", At: second + ".12Z"})
	s.PutGuardDecisionForTest(GuardDecision{ID: "newer", SessionID: "s1", RuleID: "r", Verdict: "allow", Scope: "once", At: second + ".123Z"})
	rows := s.ListGuardDecisions("s1", 1)
	if len(rows) != 1 || rows[0].ID != "newer" {
		t.Fatalf("newest row=%+v", rows)
	}
	rows = s.ListGuardDecisions("s1", 2)
	if len(rows) != 2 || rows[0].ID != "newer" || rows[1].ID != "older" {
		t.Fatalf("ordered rows=%+v", rows)
	}
}

func TestGuardDecisionRetentionAndRowCap(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetEventRetention(time.Hour, time.Hour)
	old := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano)
	base := time.Now().UTC()
	s.PutGuardDecisionForTest(GuardDecision{ID: "expired", SessionID: "s1", RuleID: "r", Verdict: "deny", Scope: "once", At: old})
	for i := 0; i < 255; i++ {
		s.PutGuardDecisionForTest(GuardDecision{ID: fmt.Sprintf("fresh-%03d", i), SessionID: "s1", RuleID: "r", Verdict: "allow", Scope: "once", At: base.Add(time.Duration(i) * time.Nanosecond).Format(time.RFC3339Nano)})
	}
	if rows := s.ListGuardDecisions("s1", 500); len(rows) != 255 {
		t.Fatalf("automatic expiration left %d rows, want 255", len(rows))
	}
	if err := s.pruneGuardDecisions(context.Background(), time.Hour, 3); err != nil {
		t.Fatal(err)
	}
	rows := s.ListGuardDecisions("s1", 500)
	if len(rows) != 3 || rows[0].ID != "fresh-254" || rows[2].ID != "fresh-252" {
		t.Fatalf("row cap kept %+v", rows)
	}
}

// Production keeps its best-effort bound; the fixture path waits out a stall.
func TestGuardDecisionDeadlineIsProductionOnly(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "guard.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	at := time.Now().UTC().Format(time.RFC3339Nano)
	stall := func(put func(GuardDecision), id string) {
		lock, err := s.db.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := lock.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
			t.Fatal(err)
		}
		go func() {
			time.Sleep(300 * time.Millisecond)
			_, _ = lock.ExecContext(context.Background(), "ROLLBACK")
			_ = lock.Close()
		}()
		put(GuardDecision{ID: id, SessionID: "s1", RuleID: "r", Verdict: "deny", Scope: "once", At: at})
	}
	stall(s.PutGuardDecision, "production")
	if h := s.WriteHealth(); !slices.Contains(h.Active, "guard decisions") {
		t.Fatalf("production write behind a 300 ms stall did not fail: %+v", h)
	}
	stall(s.PutGuardDecisionForTest, "fixture")
	if rows := s.ListGuardDecisions("s1", 10); len(rows) != 1 || rows[0].ID != "fixture" {
		t.Fatalf("rows = %+v, want only the fixture row", rows)
	}
}
