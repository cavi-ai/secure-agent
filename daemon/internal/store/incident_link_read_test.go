package store

import (
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestIncidentLinkRejectsInvalidTargetsAndRecovers(t *testing.T) {
	for _, damage := range []string{"null", "empty", "identity", "malformed", "empty id", "unavailable"} {
		t.Run(damage, func(t *testing.T) {
			s := reviewStore(t)
			if err := s.PutIncident(model.IncidentReport{ID: "incident", FlagID: "source", Timestamp: time.Now().UTC()}); err != nil {
				t.Fatal(err)
			}
			var original string
			if err := s.db.QueryRow(`SELECT report_json FROM incidents WHERE id='incident'`).Scan(&original); err != nil {
				t.Fatal(err)
			}
			var err error
			switch damage {
			case "empty id":
				_, err = s.db.Exec(`UPDATE incidents SET id='' WHERE id='incident'`)
			case "unavailable":
				_, err = s.db.Exec(`ALTER TABLE incidents RENAME TO unavailable_incidents`)
			default:
				raw := map[string]string{"null": "null", "empty": "{}", "identity": `{"id":"other"}`, "malformed": "{"}[damage]
				_, err = s.db.Exec(`UPDATE incidents SET report_json=? WHERE id='incident'`, raw)
			}
			if err != nil {
				t.Fatal(err)
			}
			if id, found := s.IncidentIDForFlag("source"); found || id != "" {
				t.Errorf("unusable incident link accepted: %q %v", id, found)
			}
			if h := s.WriteHealth(); h.ReadFailures != 1 || !slices.Contains(h.ReadActive, "incident links") {
				t.Errorf("incident link read fault hidden: %+v", h)
			}
			switch damage {
			case "empty id":
				_, err = s.db.Exec(`UPDATE incidents SET id='incident' WHERE id=''`)
			case "unavailable":
				_, err = s.db.Exec(`ALTER TABLE unavailable_incidents RENAME TO incidents`)
			default:
				_, err = s.db.Exec(`UPDATE incidents SET report_json=? WHERE id='incident'`, original)
			}
			if err != nil {
				t.Fatal(err)
			}
			if id, found := s.IncidentIDForFlag("source"); !found || id != "incident" {
				t.Errorf("repaired target unavailable: %q %v", id, found)
			}
			if h := s.WriteHealth(); h.ReadFailures != 1 || len(h.ReadActive) != 0 {
				t.Errorf("link repair lost failure history: %+v", h)
			}
		})
	}
}

func TestIncidentLinkCheckedMissingAndBatchResults(t *testing.T) {
	for _, ids := range [][]string{{"bad", "good", "bad", "missing"}, {"good", "bad", "missing", "bad"}} {
		t.Run(ids[0], func(t *testing.T) {
			s := reviewStore(t)
			if id, found, err := s.IncidentIDForFlagResult("missing"); err != nil || found || id != "" {
				t.Fatalf("missing link: %q %v %v", id, found, err)
			}
			for _, id := range []string{"bad", "good"} {
				if err := s.PutIncident(model.IncidentReport{ID: id + "-incident", FlagID: id, Timestamp: time.Now().UTC()}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.db.Exec(`UPDATE incidents SET report_json='null' WHERE id='bad-incident'`); err != nil {
				t.Fatal(err)
			}
			links, err := s.IncidentIDsForFlags(ids)
			if err == nil || len(links) != 3 || links["bad"] != "" || links["good"] != "good-incident" || links["missing"] != "" {
				t.Errorf("partial batch results: %+v %v", links, err)
			}
			if h := s.WriteHealth(); h.ReadFailures != 1 || !slices.Contains(h.ReadActive, "incident links") {
				t.Errorf("batch did not retain one read fault: %+v", h)
			}
			if _, err := s.db.Exec(`ALTER TABLE incidents RENAME TO unavailable_incidents`); err != nil {
				t.Fatal(err)
			}
			if id, found, err := s.IncidentIDForFlagResult("missing"); err == nil || found || id != "" {
				t.Errorf("unavailable link treated as missing: %q %v %v", id, found, err)
			}
			if _, err := s.db.Exec(`ALTER TABLE unavailable_incidents RENAME TO incidents`); err != nil {
				t.Fatal(err)
			}
			if id, found, err := s.IncidentIDForFlagResult("missing"); err != nil || found || id != "" {
				t.Errorf("healthy missing lookup did not recover: %q %v %v", id, found, err)
			}
			if h := s.WriteHealth(); h.ReadFailures != 2 || len(h.ReadActive) != 0 {
				t.Errorf("missing lookup lost failure history: %+v", h)
			}
		})
	}
}
