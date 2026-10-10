package store

import (
	"fmt"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestSessionIncidentsOrderByInstant(t *testing.T) {
	for _, tc := range []struct{ name, older, newer string }{
		{"nanoseconds", "2026-10-10T12:00:00.100000001Z", "2026-10-10T12:00:00.100000002Z"},
		{"fraction width", "2026-10-10T12:00:00Z", "2026-10-10T12:00:00.000000001Z"},
		{"offsets", "2026-10-10T13:00:00.900000001+01:00", "2026-10-10T08:00:00.900000002-04:00"},
		{"second boundary", "2026-10-10T12:00:00.999999999Z", "2026-10-10T12:00:01Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Open("", "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			for _, row := range []struct{ id, ts string }{{"z-older", tc.older}, {"a-newer", tc.newer}} {
				at, err := time.Parse(time.RFC3339Nano, row.ts)
				if err != nil {
					t.Fatal(err)
				}
				if err := s.PutIncident(model.IncidentReport{ID: row.id, SessionID: "owned", Timestamp: at}); err != nil {
					t.Fatal(err)
				}
				// Keep historical offsets and fractional widths in the SQL fixture.
				if _, err := s.db.Exec("UPDATE incidents SET created_at=? WHERE id=?", row.ts, row.id); err != nil {
					t.Fatal(err)
				}
			}
			got, err := s.SessionIncidents("owned")
			if err != nil || len(got) != 2 || got[0].ID != "a-newer" || got[1].ID != "z-older" {
				t.Fatalf("incident order: %+v %v", got, err)
			}
		})
	}
}

func TestSessionOutcomesIncidentLimitKeepsNewest(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	base := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	if err := s.UpsertSession(model.Session{ID: "owned", Harness: "codex", RootPID: 42, RootStartedAt: base.Format(time.RFC3339Nano), Status: model.SessionEnded, StartedAt: base, LastSeenAt: base}); err != nil {
		t.Fatal(err)
	}
	for i := range 100 {
		if err := s.PutIncident(model.IncidentReport{ID: fmt.Sprintf("older-%03d", i), SessionID: "owned", Timestamp: base}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.PutIncident(model.IncidentReport{ID: "newest", SessionID: "owned", Timestamp: base.Add(time.Nanosecond), RotateList: []model.RotateItem{{ID: "key", Name: "Key", Action: "Revoke affected key"}}}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutIncident(model.IncidentReport{ID: "other-session", SessionID: "other", Timestamp: base.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	inc, err := s.GetIncident("newest")
	if err != nil {
		t.Fatal(err)
	}
	view := inc.Remediation
	if _, err := s.ReportIncidentRemediation(model.IncidentRemediationRequest{ID: inc.ID, StepID: view.Steps[0].ID, ExpectedRevision: view.Revision, ExpectedEvidence: view.EvidenceRevision, Status: "reported"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SetIncidentStatusResult("newest", "resolved", "reviewed"); err != nil {
		t.Fatal(err)
	}
	history := s.SessionOutcomes("owned")
	if len(history.Incidents) != 100 {
		t.Fatalf("bounded history count: %d", len(history.Incidents))
	}
	if history.Incidents[0].ID != "newest" || history.Incidents[99].ID != "older-001" {
		t.Fatalf("newest incident excluded or wrong tie order: first=%s last=%s", history.Incidents[0].ID, history.Incidents[99].ID)
	}
	if history.Incidents[0].Remediation.Steps[0].Status != "reported" {
		t.Fatal("history lost saved remediation")
	}
	if evidence := history.Evidence.Incidents; !evidence.Available || !evidence.AtLimit || evidence.Limit != 100 {
		t.Fatalf("bounded incident evidence: %+v", evidence)
	}
}
