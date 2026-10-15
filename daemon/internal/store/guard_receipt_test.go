package store

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGuardResultsRetainExactPermissionAndReadFailures(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Unknown optional metadata remains unknown for old records.
	for _, raw := range []string{
		`{"id":"new","session_id":"owned","rule_id":"r","verdict":"allow","scope":"exact","resolution_id":"prompt","scope_ids":["permission"],"reason":""}`,
		`{"id":"old","session_id":"owned","rule_id":"r","verdict":"deny","scope":"once"}`,
		`{"id":"foreign","session_id":"other","rule_id":"r","verdict":"allow","scope":"once"}`,
	} {
		var d GuardDecision
		if err := json.Unmarshal([]byte(raw), &d); err != nil {
			t.Fatal(err)
		}
		d.At = time.Now().UTC().Format(time.RFC3339Nano)
		s.PutGuardDecisionForTest(d)
	}
	out := s.SessionOutcomes("owned")
	b, _ := json.Marshal(out)
	if !strings.Contains(string(b), `"guards":[`) || !strings.Contains(string(b), `"scope_ids":["permission"]`) || strings.Contains(string(b), `foreign`) {
		t.Fatalf("missing or crossed receipt: %s", b)
	}
	if _, err := s.db.Exec(`ALTER TABLE guard_decisions RENAME TO unavailable_guards`); err != nil {
		t.Fatal(err)
	}
	b, _ = json.Marshal(s.SessionOutcomes("owned"))
	var history struct {
		Evidence map[string]ReportSourceEvidence
	}
	if err := json.Unmarshal(b, &history); err != nil {
		t.Fatal(err)
	}
	if e, ok := history.Evidence["guards"]; !ok || e.Available {
		t.Fatalf("failed guard read reported available: %s", b)
	}
}

func TestGuardReceiptMigrationPreservesLegacyUnknowns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(guardDecisionsSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO guard_decisions VALUES ('old','session','env','allow','always',?)`, time.Now().UTC().Format(guardDecisionTimeLayout)); err != nil {
		t.Fatal(err)
	}
	db.Close()
	s, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rows, err := s.GuardDecisionHistory("session", 200)
	if err != nil || len(rows) != 1 || rows[0].ID != "old" || rows[0].ResolutionID != "" || len(rows[0].ScopeIDs) != 0 {
		t.Fatalf("legacy metadata invented: %+v %v", rows, err)
	}
	for _, raw := range []string{`{broken`, `{"scope_ids":"wrong-type"}`} {
		if _, err := s.db.Exec(`UPDATE guard_decisions SET receipt_json=?`, raw); err != nil {
			t.Fatal(err)
		}
		out := s.SessionOutcomes("session")
		if out.Evidence.Guards.Available || len(out.Guards) != 0 || !out.Evidence.Reviews.Available {
			t.Fatalf("bad source erased siblings or escaped: %+v", out)
		}
	}
}
