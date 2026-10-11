package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestIncidentWorkflowTargetsOneReport(t *testing.T) {
	for _, tc := range []struct {
		name, alias, target string
		reports             []model.IncidentReport
		aggregated          bool
	}{
		{"direct identity", "target", "target", []model.IncidentReport{{ID: "target", FlagID: "own"}, {ID: "other", FlagID: "target"}}, false},
		{"shared original flag", "shared", "target", []model.IncidentReport{{ID: "other", FlagID: "shared"}, {ID: "target", FlagID: "shared"}}, false},
		{"aggregated flag", "repeat", "target", []model.IncidentReport{{ID: "other", FlagID: "unrelated"}, {ID: "target", FlagID: "first"}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "workflow.db")
			s, err := Open(path, "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			now := time.Date(2026, 10, 10, 12, 0, 0, 100000001, time.UTC)
			for i, inc := range tc.reports {
				inc.Timestamp = now.Add(time.Duration(i))
				if err := s.PutIncident(inc); err != nil {
					t.Fatal(err)
				}
			}
			if tc.aggregated {
				if _, ok := s.AggregateIntoIncident(tc.target, tc.alias, now.Add(time.Second)); !ok {
					t.Fatal("could not aggregate flag")
				}
			}
			if report, err := s.GetIncident(tc.alias); err != nil || report.ID != tc.target {
				t.Fatalf("detail identity: %+v %v", report, err)
			}
			protected, updated, err := s.SetIncidentStatusResult("other", "acknowledged", "")
			if err != nil || !updated {
				t.Fatal("could not acknowledge sibling", err)
			}
			if wf, found, err := s.IncidentStatusResult(tc.alias); err != nil || !found || wf.Status != "open" {
				t.Errorf("workflow disagrees with detail: %+v %v %v", wf, found, err)
			}
			wf, updated, err := s.SetIncidentStatusResult(tc.alias, "resolved", "reviewed")
			if err != nil || !updated || wf.Status != "resolved" || wf.ResolutionNote != "reviewed" {
				t.Errorf("alias resolution: %+v %v %v", wf, updated, err)
			}
			assertSaved := func(s *Store) {
				t.Helper()
				if got, found, err := s.IncidentStatusResult(tc.target); err != nil || !found || got != wf {
					t.Errorf("target differs from returned workflow: %+v %v %v", got, found, err)
				}
				if got, found, err := s.IncidentStatusResult("other"); err != nil || !found || got != protected {
					t.Errorf("alias update changed sibling: %+v %v %v", got, found, err)
				}
			}
			assertSaved(s)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(path, "")
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			assertSaved(reopened)
		})
	}
}
