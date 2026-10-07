package store

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// The flag statements on hot paths seek an index instead of scanning or
// sorting the whole table.
func TestFlagHotPathsUseIndexes(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if plan := queryPlan(t, s, reattributeFlagsSQL, "claude", 7, "2026-10-07T00:00:00Z"); !strings.Contains(plan, "idx_flags_pid") {
		t.Errorf("reattribute plan = %q, want idx_flags_pid", plan)
	}
	if plan := queryPlan(t, s, trimFlagsSQL, maxFlags); !strings.Contains(plan, "idx_flags_time") || strings.Contains(plan, "TEMP B-TREE") {
		t.Errorf("trim plan = %q, want idx_flags_time without a sort", plan)
	}
	for _, f := range []FlagFilter{{}, {Unacted: true}, {MinSeverity: 3}} {
		q, args := flagQuery(f)
		if plan := queryPlan(t, s, q, args...); !strings.Contains(plan, "idx_flags_time") || strings.Contains(plan, "TEMP B-TREE") {
			t.Errorf("QueryFlags(%+v) plan = %q, want idx_flags_time without a sort", f, plan)
		}
	}
	if plan := queryPlan(t, s, `SELECT id FROM flags WHERE rule = ? AND agent = ?`, "r", "claude"); !strings.Contains(plan, "idx_flags_rule_agent") {
		t.Errorf("rule/agent plan = %q, want idx_flags_rule_agent", plan)
	}

	if plan := queryPlan(t, s, findOpenIncidentSQL, "r", "s1", "subj"); !strings.Contains(plan, "idx_incidents_open_key") {
		t.Errorf("open-incident plan = %q, want idx_incidents_open_key", plan)
	}
	if plan := queryPlan(t, s, trimIncidentsSQL, maxIncidents); !strings.Contains(plan, "idx_incidents_time") || strings.Contains(plan, "TEMP B-TREE") {
		t.Errorf("incident trim plan = %q, want idx_incidents_time without a sort", plan)
	}
	if plan := queryPlan(t, s, `SELECT report_json FROM incidents WHERE id = ? OR flag_id = ?`, "i", "f"); strings.Contains(plan, "SCAN incidents") {
		t.Errorf("incident by id-or-flag plan = %q, want index lookups", plan)
	}
}

// Trimming keeps the newest flags by instant and deletes nothing at or under
// the cap.
func TestTrimFlagsDeletesOnlyTheOldestOverflow(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	base := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		s.PutFlag(model.Flag{ID: fmt.Sprintf("f%d", i), Rule: "r", Severity: 2, TS: base.Add(time.Duration(i) * time.Minute)})
	}
	count := func() int {
		var n int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM flags`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if _, err := s.db.Exec(trimFlagsSQL, 5); err != nil || count() != 5 {
		t.Fatalf("at the cap: err=%v count=%d, want 5", err, count())
	}
	if _, err := s.db.Exec(trimFlagsSQL, 3); err != nil {
		t.Fatal(err)
	}
	var ids []string
	rows, err := s.db.Query(`SELECT id FROM flags ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if strings.Join(ids, ",") != "f2,f3,f4" {
		t.Fatalf("kept %v, want the newest three f2,f3,f4", ids)
	}
}
