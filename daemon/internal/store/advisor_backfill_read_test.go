package store

import (
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestAdvisorBackfillRejectsCorruptRowsAndRecovers(t *testing.T) {
	for _, tc := range []struct{ name, damage, repair string }{
		{"scan", `UPDATE flags SET pid='invalid' WHERE id='bad'`, `UPDATE flags SET pid=42 WHERE id='bad'`},
		{"evidence", `UPDATE flags SET evidence='invalid' WHERE id='bad'`, `UPDATE flags SET evidence=NULL WHERE id='bad'`},
		{"timestamp", `UPDATE flags SET ts='2026-99-99T00:00:00Z' WHERE id='bad'`, ""},
		{"timestamp encoding", `UPDATE flags SET ts='9999-01-01 00:00:00' WHERE id='bad'`, ""},
		{"repeat timestamp", `UPDATE flags SET last_seen='invalid' WHERE id='bad'`, `UPDATE flags SET last_seen=NULL WHERE id='bad'`},
		{"process", `UPDATE flags SET process='invalid' WHERE id='bad'`, `UPDATE flags SET process=NULL WHERE id='bad'`},
		{"advisor query", `ALTER TABLE advisor_verdicts RENAME TO unavailable_advice`, `ALTER TABLE unavailable_advice RENAME TO advisor_verdicts`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := reviewStore(t)
			at := time.Now().UTC()
			for i, id := range []string{"bad", "good"} {
				if _, err := s.PutFlag(model.Flag{ID: id, Rule: "rule", Severity: 3, PID: 42, TS: at.Add(time.Duration(i) * time.Second)}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.db.Exec(tc.damage); err != nil {
				t.Fatal(err)
			}
			limit := 25
			if tc.name == "timestamp" {
				limit = 1 // Invalid dates must not hide behind newer valid rows.
			}
			if rows, err := s.CriticalFlagsMissingAdvisorResult(at.Add(-time.Hour), limit); err == nil || rows != nil {
				t.Errorf("corrupt or partial backfill returned: rows=%+v err=%v", rows, err)
			}
			if h := s.WriteHealth(); h.ReadFailures != 1 || !slices.Equal(h.ReadActive, []string{"advisor backfill"}) || h.Failures != 0 {
				t.Errorf("backfill read failure hidden: %+v", h)
			}
			if tc.repair != "" {
				if _, err := s.db.Exec(tc.repair); err != nil {
					t.Fatal(err)
				}
			} else if _, err := s.db.Exec(`UPDATE flags SET ts=? WHERE id='bad'`, at.Format(time.RFC3339Nano)); err != nil {
				t.Fatal(err)
			}
			if rows, err := s.CriticalFlagsMissingAdvisorResult(at.Add(-time.Hour), 25); err != nil || len(rows) != 2 || rows[0].ID != "good" || rows[1].ID != "bad" {
				t.Fatalf("backfill recovery: rows=%+v err=%v", rows, err)
			}
			if h := s.WriteHealth(); h.ReadFailures != 1 || len(h.ReadActive) != 0 {
				t.Errorf("backfill recovery lost failure history: %+v", h)
			}
		})
	}
}

func TestAdvisorBackfillNullableMetadataAndHealthyAbsence(t *testing.T) {
	s := reviewStore(t)
	at := time.Now().UTC()
	if _, err := s.PutFlag(model.Flag{ID: "legacy", Severity: 3, TS: at, PID: 42}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE flags SET rule=NULL, agent=NULL, session_id=NULL, workspace=NULL,
	 evidence=NULL, acknowledged=NULL, ack_reason=NULL, process=NULL, repeats=NULL, last_seen=NULL WHERE id='legacy'`); err != nil {
		t.Fatal(err)
	}
	rows, err := s.CriticalFlagsMissingAdvisorResult(at.Add(-time.Hour), 1)
	if err != nil || len(rows) != 1 || rows[0].ID != "legacy" || !rows[0].TS.Equal(at) || rows[0].PID != 42 {
		t.Fatalf("nullable legacy flag: rows=%+v err=%v", rows, err)
	}
	if err := s.PutAdvisorVerdict("legacy", "flag", model.AdvisorVerdict{Assessment: "benign", Rationale: "routine"}); err != nil {
		t.Fatal(err)
	}
	rows, err = s.CriticalFlagsMissingAdvisorResult(at.Add(-time.Hour), 1)
	if err != nil || rows == nil || len(rows) != 0 {
		t.Fatalf("healthy absence: rows=%+v err=%v", rows, err)
	}
	if h := s.WriteHealth(); h.ReadFailures != 0 || len(h.ReadActive) != 0 {
		t.Errorf("healthy reads marked failed: %+v", h)
	}
}
