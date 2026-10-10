package store

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestOpenIncidentLookupDistinguishesMissingFromUnavailable(t *testing.T) {
	for _, tc := range []struct{ name, fault, repair string }{
		{"scan", `UPDATE incidents SET id=NULL`, `UPDATE incidents SET id='incident'`},
		{"empty identity", `UPDATE incidents SET id=''`, `UPDATE incidents SET id='incident'`},
		{"query", `ALTER TABLE incidents RENAME TO unavailable_incidents`, `ALTER TABLE unavailable_incidents RENAME TO incidents`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Open("", "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if id, found, err := s.FindOpenIncidentResult("rule", "session", "subject"); err != nil || found || id != "" {
				t.Fatalf("missing incident: %q %v %v", id, found, err)
			}
			if err := s.PutIncident(model.IncidentReport{ID: "incident", Rule: "rule", SessionID: "session", Subject: "subject", Timestamp: time.Now()}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec(tc.fault); err != nil {
				t.Fatal(err)
			}
			if id, found, err := s.FindOpenIncidentResult("rule", "session", "subject"); err == nil || found || id != "" {
				t.Fatalf("failed lookup reported a target or absence: %q %v %v", id, found, err)
			}
			if h := s.WriteHealth(); h.ReadFailures != 1 || len(h.ReadActive) != 1 || h.ReadActive[0] != "incident lookup" {
				t.Fatalf("lookup fault hidden: %+v", h)
			}
			if _, err := s.db.Exec(tc.repair); err != nil {
				t.Fatal(err)
			}
			if id, found, err := s.FindOpenIncidentResult("rule", "session", "subject"); err != nil || !found || id != "incident" {
				t.Fatalf("lookup did not recover: %q %v %v", id, found, err)
			}
			if h := s.WriteHealth(); h.ReadFailures != 1 || len(h.ReadActive) != 0 {
				t.Fatalf("lookup recovery health: %+v", h)
			}
		})
	}
}
