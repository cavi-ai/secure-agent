package store

import (
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestRuleCountsResultWindowsScopeAndEmpty(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	for _, f := range []model.Flag{
		{ID: "recent", Rule: "rule", Agent: "codex", TS: now.Add(-24 * time.Hour)},
		{ID: "week-boundary", Rule: "rule", Agent: "codex", TS: now.Add(-7 * 24 * time.Hour)},
		{ID: "month", Rule: "rule", Agent: "codex", TS: now.Add(-8 * 24 * time.Hour)},
		{ID: "month-boundary", Rule: "rule", Agent: "codex", TS: now.Add(-30 * 24 * time.Hour)},
		{ID: "old", Rule: "rule", Agent: "codex", TS: now.Add(-31 * 24 * time.Hour)},
		{ID: "other-rule", Rule: "other", Agent: "codex", TS: now},
		{ID: "other-agent", Rule: "rule", Agent: "other", TS: now},
	} {
		if _, err := s.PutFlag(f); err != nil {
			t.Fatal(err)
		}
	}
	if d7, d30, err := s.RuleCountsResult("rule", "codex", now); err != nil || d7 != 2 || d30 != 4 {
		t.Fatalf("window counts: %d, %d, %v", d7, d30, err)
	}
	if d7, d30, err := s.RuleCountsResult("missing", "codex", now); err != nil || d7 != 0 || d30 != 0 {
		t.Fatalf("healthy empty counts: %d, %d, %v", d7, d30, err)
	}
}

func TestRuleCountsResultFailureAndRecovery(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.db.Exec("ALTER TABLE flags RENAME TO unavailable_flags"); err != nil {
		t.Fatal(err)
	}
	if d7, d30, err := s.RuleCountsResult("rule", "codex", time.Now()); err == nil || d7 != 0 || d30 != 0 {
		t.Fatalf("failed counts: %d, %d, %v", d7, d30, err)
	}
	if h := s.WriteHealth(); h.ReadFailures != 1 || !slices.Equal(h.ReadActive, []string{"rule history"}) || h.Failures != 0 {
		t.Fatalf("read fault health: %+v", h)
	}
	if _, err := s.db.Exec("ALTER TABLE unavailable_flags RENAME TO flags"); err != nil {
		t.Fatal(err)
	}
	if d7, d30, err := s.RuleCountsResult("rule", "codex", time.Now()); err != nil || d7 != 0 || d30 != 0 {
		t.Fatalf("recovered empty counts: %d, %d, %v", d7, d30, err)
	}
	if h := s.WriteHealth(); h.ReadFailures != 1 || len(h.ReadActive) != 0 {
		t.Fatalf("recovered health: %+v", h)
	}
	s.Close()
	if d7, d30, err := s.RuleCountsResult("rule", "codex", time.Now()); err == nil || d7 != 0 || d30 != 0 {
		t.Fatalf("closed counts: %d, %d, %v", d7, d30, err)
	}
	if h := s.WriteHealth(); h.ReadFailures != 2 || !slices.Equal(h.ReadActive, []string{"rule history"}) {
		t.Fatalf("closed read health: %+v", h)
	}
}
