package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestIncidentAggregationSharesDetailIdentity(t *testing.T) {
	for _, tc := range []struct{ name, key, target string }{
		{"exact identity wins", "older", "older"},
		{"opening flag selects newest", "opening", "newer"},
		{"aggregated flag", "repeat", "newer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Open("", "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			now := time.Now().UTC()
			for i, id := range []string{"older", "newer"} {
				if err := s.PutIncident(model.IncidentReport{ID: id, FlagID: "opening", Timestamp: now.Add(time.Duration(i)), SessionID: "session", RotateList: []model.RotateItem{{Name: "Key", Action: "Revoke key"}}}); err != nil {
					t.Fatal(err)
				}
			}
			for _, flag := range []string{"repeat", "older"} {
				if _, ok := s.AggregateIntoIncident("newer", flag, now); !ok {
					t.Fatal("seed aggregation failed")
				}
			}
			before, err := s.GetIncident(tc.key)
			if err != nil || before.ID != tc.target {
				t.Fatalf("detail: %+v %v", before, err)
			}
			got, ok := s.AggregateIntoIncident(tc.key, "next", now.Add(time.Minute))
			if !ok || got.ID != before.ID || got.AggregateCount != before.AggregateCount+1 {
				t.Fatalf("aggregation disagrees with detail: %+v %v", got, ok)
			}
			view := got.Remediation
			updated, err := s.ReportIncidentRemediation(model.IncidentRemediationRequest{ID: tc.key, StepID: view.Steps[0].ID, ExpectedRevision: view.Revision, ExpectedEvidence: view.EvidenceRevision, Status: "reported"})
			if err != nil || updated.ID != tc.target {
				t.Fatalf("remediation disagrees with detail: %+v %v", updated, err)
			}
			rows, err := s.SessionIncidents("session")
			if err != nil || len(rows) != 2 {
				t.Fatalf("session history: %+v %v", rows, err)
			}
			for _, row := range rows {
				if row.ID == tc.target && !reflect.DeepEqual(row.Remediation, updated.Remediation) {
					t.Fatal("history lost remediation")
				}
			}
		})
	}
}

func TestAbsorbOpenIncidentReturnsPersistenceFailure(t *testing.T) {
	for _, tc := range []struct{ name, fault, repair string }{
		{"read only", `PRAGMA query_only=ON`, `PRAGMA query_only=OFF`},
		{"ignored write", `CREATE TRIGGER fail_absorb BEFORE UPDATE ON incidents BEGIN SELECT RAISE(IGNORE); END`, `DROP TRIGGER fail_absorb`},
		{"corrupt report", `UPDATE incidents SET report_json='null'`, ""},
		{"corrupt remediation", `UPDATE incidents SET remediation_json='null'`, `UPDATE incidents SET remediation_json=''`},
		{"invalid result", `CREATE TRIGGER fail_absorb AFTER UPDATE ON incidents BEGIN UPDATE incidents SET report_json='null' WHERE id=NEW.id; END`, `DROP TRIGGER fail_absorb`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Open("", "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			now := time.Now().UTC()
			if report, persisted, err := s.AbsorbOpenIncident("rule", "session", "subject", "second", now); err != nil || persisted || report.ID != "" {
				t.Fatalf("missing target: %+v %v %v", report, persisted, err)
			}
			if err := s.PutIncident(model.IncidentReport{ID: "incident", FlagID: "first", Rule: "rule", SessionID: "session", Subject: "subject", Timestamp: now}); err != nil {
				t.Fatal(err)
			}
			var original string
			if err := s.db.QueryRow(`SELECT report_json FROM incidents WHERE id='incident'`).Scan(&original); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec(tc.fault); err != nil {
				t.Fatal(err)
			}
			report, persisted, err := s.AbsorbOpenIncident("rule", "session", "subject", "second", now.Add(time.Minute))
			if err == nil || persisted || report.ID != "" {
				t.Fatalf("failed absorb reported success or absence: %+v %v %v", report, persisted, err)
			}
			var count int
			if err := s.db.QueryRow(`SELECT aggregate_count FROM incidents WHERE id='incident'`).Scan(&count); err != nil || count != 1 {
				t.Fatalf("failed absorb changed evidence: %d %v", count, err)
			}
			if tc.repair != "" {
				if _, err := s.db.Exec(tc.repair); err != nil {
					t.Fatal(err)
				}
			} else if _, err := s.db.Exec(`UPDATE incidents SET report_json=? WHERE id='incident'`, original); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				report, persisted, err = s.AbsorbOpenIncident("rule", "session", "subject", "second", now.Add(time.Minute))
				if err != nil || !persisted || report.ID != "incident" || report.AggregateCount != 2 {
					t.Fatalf("recovery/replay: %+v %v %v", report, persisted, err)
				}
				saved, err := s.GetIncident("second")
				if err != nil || !reflect.DeepEqual(saved, &report) {
					t.Fatalf("returned report differs from storage: %+v %v", saved, err)
				}
			}
		})
	}
}
