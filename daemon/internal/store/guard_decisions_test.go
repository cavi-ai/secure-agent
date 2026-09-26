package store

import (
	"path/filepath"
	"testing"
)

func TestGuardDecisionStorePersistsRedactedRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard.db")
	s, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	s.PutGuardDecision(GuardDecision{ID: "d1", SessionID: "s1", RuleID: "cloud-creds", Verdict: "deny", Scope: "once", At: "2026-09-26T10:00:00Z"})
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
