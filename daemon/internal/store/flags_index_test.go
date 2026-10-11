package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// A store whose stamps include 'now' (which datetime() refuses inside an
// index) or malformed text still opens and accepts writes/retention; only the
// flag retention index is skipped. Flag reads reject malformed timestamps.
func TestOpenSurvivesStampsTheTimeIndexesRefuse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE flags (id TEXT PRIMARY KEY, rule TEXT, severity INT, ts TEXT, pid INT, agent TEXT, session_id TEXT, workspace TEXT, evidence TEXT)`,
		`CREATE TABLE incidents (id TEXT PRIMARY KEY, flag_id TEXT, pid INT, risk TEXT, report_json TEXT, created_at TEXT, status TEXT DEFAULT 'open', acknowledged_at TEXT, resolved_at TEXT, resolution_note TEXT)`,
		`INSERT INTO flags (id, rule, severity, ts, pid, agent, evidence) VALUES
			('f-now', 'r', 2, 'now', 0, 'claude', '[]'), ('f-bad', 'r', 2, 'garbage', 0, 'claude', '[]'),
			('f-ok', 'r', 2, '2026-10-07T12:00:00Z', 0, 'claude', '[]')`,
		`INSERT INTO incidents (id, created_at) VALUES ('i-now', 'NOW'), ('i-ok', '2026-10-07T12:00:00Z')`,
	} {
		if _, err := raw.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	raw.Close()

	s, err := Open(path, "")
	if err != nil {
		t.Fatalf("Open with a 'now' stamp: %v", err)
	}
	defer s.Close()
	if _, err := s.PutFlag(model.Flag{ID: "f-new", Rule: "r", Severity: 2, Agent: "claude", TS: time.Date(2026, 10, 7, 13, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.db.QueryRow("SELECT count(*) FROM flags").Scan(&count); err != nil || count != 4 {
		t.Fatalf("flags retained after open: count=%d err=%v", count, err)
	}
	if got, err := s.QueryFlagsResult(FlagFilter{Limit: 10}); err == nil || got != nil {
		t.Fatalf("malformed timestamps returned as valid flags: %+v, %v", got, err)
	}
	if _, err := s.db.Exec(trimFlagsSQL, 2); err != nil {
		t.Fatalf("trim without the time index: %v", err)
	}
	if _, err := s.db.Exec("UPDATE flags SET ts='2026-10-07T12:00:00Z' WHERE ts='now' OR ts='garbage'"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.QueryFlagsResult(FlagFilter{Limit: 10}); err != nil || len(got) != 2 {
		t.Fatalf("read after timestamp repair: %+v, %v", got, err)
	}
}

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
	if plan := queryPlan(t, s, ruleCountsSQL, "a", "b", "r", "claude"); !strings.Contains(plan, "idx_flags_rule_agent") {
		t.Errorf("RuleCounts plan = %q, want idx_flags_rule_agent", plan)
	}
	for _, agent := range []string{"", "claude"} {
		q, args := ackRuleHostQuery("r", agent)
		if plan := queryPlan(t, s, q, args...); !strings.Contains(plan, "idx_flags_rule_agent") {
			t.Errorf("AcknowledgeRuleHost(agent=%q) plan = %q, want idx_flags_rule_agent", agent, plan)
		}
	}

	if plan := queryPlan(t, s, findOpenIncidentSQL, "r", "s1", "subj"); !strings.Contains(plan, "idx_incidents_open_key") {
		t.Errorf("open-incident plan = %q, want idx_incidents_open_key", plan)
	}
	if plan := queryPlan(t, s, trimIncidentsSQL, maxIncidents); !strings.Contains(plan, "idx_incidents_instant_time") || strings.Contains(plan, "TEMP B-TREE") {
		t.Errorf("incident trim plan = %q, want idx_incidents_instant_time without a sort", plan)
	}
	if plan := queryPlan(t, s, `SELECT report_json FROM incidents WHERE id = ? OR flag_id = ?`, "i", "f"); strings.Contains(plan, "SCAN incidents") {
		t.Errorf("incident by id-or-flag plan = %q, want index lookups", plan)
	}
}

// Flag trimming keeps the same rows the previous whole-table statement kept,
// including NULL, empty, unparseable, offset, sub-second and tied stamps.
func TestFlagTrimKeepsWhatThePreviousStatementKept(t *testing.T) {
	stamps := []any{nil, "", "garbage",
		"2026-10-07T12:00:00Z", "2026-10-07T13:30:00+02:00", "2026-10-07T07:15:00-05:00",
		"2026-10-07T12:00:00.5Z", "2026-10-07T12:05:00Z", "2026-10-07T12:05:00Z",
		"2026-10-07T11:00:00Z", "2026-10-07T12:20:00Z", "2026-10-07T12:20:00.000000001Z"}
	for _, tc := range []struct {
		table, insert, previous, current, column string
		limit                                    int
	}{
		{"flags", `INSERT INTO flags (id, rule, ts) VALUES (?, 'r', ?)`,
			`DELETE FROM flags WHERE rowid NOT IN (SELECT rowid FROM flags ORDER BY datetime(ts) DESC, ts DESC LIMIT ?)`,
			trimFlagsSQL, "ts", 5},
	} {
		kept := func(trim string) []string {
			s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			for i, ts := range stamps {
				if _, err := s.db.Exec(tc.insert, fmt.Sprintf("x%d", i), ts); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.db.Exec(trim, tc.limit); err != nil {
				t.Fatal(err)
			}
			rows, err := s.db.Query(`SELECT COALESCE(` + tc.column + `, '<null>') FROM ` + tc.table + ` ORDER BY 1`)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			var out []string
			for rows.Next() {
				var v string
				if err := rows.Scan(&v); err != nil {
					t.Fatal(err)
				}
				out = append(out, v)
			}
			return out
		}
		want, got := kept(tc.previous), kept(tc.current)
		if len(want) != tc.limit || strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%s: kept %q, previous statement kept %q", tc.table, got, want)
		}
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
