package store

import (
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestIncidentCreationMarshalFailureIsTracked(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.PutIncident(model.IncidentReport{ID: "invalid", Timestamp: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("invalid incident reported persistence success")
	}
	h := s.WriteHealth()
	if h.Failures != 1 || !slices.Equal(h.Active, []string{"incidents"}) {
		t.Fatalf("incident serialization failure hidden: %+v", h)
	}
	if got := s.RecentIncidents(10); len(got) != 0 {
		t.Fatalf("invalid incident was persisted: %+v", got)
	}
}

func TestIncidentCreationRejectsZeroRowInsert(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.db.Exec(`CREATE TRIGGER skip_incident BEFORE INSERT ON incidents BEGIN SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatal(err)
	}
	incident := model.IncidentReport{ID: "incident", Timestamp: time.Now()}
	if err := s.PutIncident(incident); err == nil {
		t.Fatal("zero-row insert reported persistence success")
	}
	h := s.WriteHealth()
	if h.Failures != 1 || !slices.Equal(h.Active, []string{"incidents"}) {
		t.Fatalf("zero-row incident failure hidden: %+v", h)
	}
	if got := s.RecentIncidents(10); len(got) != 0 {
		t.Fatalf("rejected incident was persisted: %+v", got)
	}
	if _, err := s.db.Exec("DROP TRIGGER skip_incident"); err != nil {
		t.Fatal(err)
	}
	if err := s.PutIncident(incident); err != nil {
		t.Fatal(err)
	}
	h = s.WriteHealth()
	if h.Failures != 1 || len(h.Active) != 0 {
		t.Fatalf("recovery lost failure history or retained fault: %+v", h)
	}
}

func TestIncidentAggregationFailureAndRecovery(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "events.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	s.PutIncident(model.IncidentReport{ID: "incident", FlagID: "first", Timestamp: now, AggregateCount: 1})
	if _, err := s.db.Exec("PRAGMA query_only = ON"); err != nil {
		t.Fatal(err)
	}
	if report, ok := s.AggregateIntoIncident("incident", "second", now.Add(time.Minute)); ok || report.ID != "" {
		t.Fatalf("failed update reported a persisted delta: %+v, %v", report, ok)
	}
	if got, err := s.GetIncident("incident"); err != nil || got.AggregateCount != 1 || got.LastFlagAt != nil {
		t.Fatalf("failed aggregation changed the saved report: %+v, %v", got, err)
	}
	if _, ok := s.IncidentIDForFlag("second"); ok {
		t.Fatal("failed aggregation saved the new flag link")
	}
	h := s.WriteHealth()
	if h.Failures != 1 || !slices.Equal(h.Active, []string{"incident aggregation"}) {
		t.Fatalf("aggregation failure hidden: %+v", h)
	}
	if _, err := s.db.Exec("PRAGMA query_only = OFF"); err != nil {
		t.Fatal(err)
	}
	s.PutIncident(model.IncidentReport{ID: "other", FlagID: "other", Timestamp: now})
	if _, ok := s.AggregateIntoIncident("missing", "second", now); ok {
		t.Fatal("missing incident reported success")
	}
	h = s.WriteHealth()
	if h.Failures != 1 || !slices.Equal(h.Active, []string{"incident aggregation"}) {
		t.Fatalf("unrelated write or missing row cleared aggregation failure: %+v", h)
	}
	// A successful SQL statement that changes no row must not clear a fault
	// or publish a report that the database never saved.
	if _, err := s.db.Exec(`CREATE TRIGGER skip_aggregation BEFORE UPDATE ON incidents BEGIN SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatal(err)
	}
	if report, ok := s.AggregateIntoIncident("incident", "second", now.Add(time.Minute)); ok || report.ID != "" {
		t.Fatalf("zero-row update reported a persisted delta: %+v, %v", report, ok)
	}
	h = s.WriteHealth()
	if h.Failures != 1 || !slices.Equal(h.Active, []string{"incident aggregation"}) {
		t.Fatalf("zero-row update cleared aggregation failure: %+v", h)
	}
	if _, err := s.db.Exec("DROP TRIGGER skip_aggregation"); err != nil {
		t.Fatal(err)
	}
	report, ok := s.AggregateIntoIncident("incident", "second", now.Add(time.Minute))
	if !ok || report.AggregateCount != 2 || report.LastFlagAt == nil || !report.LastFlagAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("aggregation did not recover: %+v, %v", report, ok)
	}
	if got, err := s.GetIncident("incident"); err != nil || got.AggregateCount != report.AggregateCount || got.LastFlagAt == nil || !got.LastFlagAt.Equal(*report.LastFlagAt) {
		t.Fatalf("delta disagrees with persisted report: %+v, %v", got, err)
	}
	if id, ok := s.IncidentIDForFlag("second"); !ok || id != "incident" {
		t.Fatal("recovered aggregation did not save the flag link")
	}
	h = s.WriteHealth()
	if h.Failures != 1 || len(h.Active) != 0 {
		t.Fatalf("recovery lost failure history or retained the fault: %+v", h)
	}
}

func TestIncidentAggregationRejectsCorruptEvidence(t *testing.T) {
	for _, tc := range []struct{ name, column, payload, flagID string }{
		{"report syntax", "report_json", "{", "second"},
		{"null report", "report_json", "null", "second"},
		{"missing report identity", "report_json", `{}`, "second"},
		{"mismatched report identity", "report_json", `{"id":"other"}`, "second"},
		{"replayed mismatched report identity", "report_json", `{"id":"other"}`, "first"},
		{"flag IDs syntax", "flag_ids", "[", "second"},
		{"flag IDs object", "flag_ids", "{}", "second"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Open("", "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			now := time.Now()
			if err := s.PutIncident(model.IncidentReport{ID: "incident", FlagID: "first", Timestamp: now, AggregateCount: 1}); err != nil {
				t.Fatal(err)
			}
			if err := s.PutIncident(model.IncidentReport{ID: "other", FlagID: "other", Timestamp: now}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec("UPDATE incidents SET "+tc.column+" = ? WHERE id = 'incident'", tc.payload); err != nil {
				t.Fatal(err)
			}
			var beforeReport, beforeIDs string
			if err := s.db.QueryRow("SELECT report_json, flag_ids FROM incidents WHERE id = 'incident'").Scan(&beforeReport, &beforeIDs); err != nil {
				t.Fatal(err)
			}
			if report, ok := s.AggregateIntoIncident("incident", tc.flagID, now); ok || report.ID != "" {
				t.Fatalf("corrupt evidence reported aggregation success: %+v, %v", report, ok)
			}
			var afterReport, afterIDs string
			var count int
			if err := s.db.QueryRow("SELECT report_json, flag_ids, aggregate_count FROM incidents WHERE id = 'incident'").Scan(&afterReport, &afterIDs, &count); err != nil {
				t.Fatal(err)
			}
			if afterReport != beforeReport || afterIDs != beforeIDs || count != 1 {
				t.Fatal("aggregation overwrote corrupt evidence or partially changed its count")
			}
			h := s.WriteHealth()
			if h.Failures != 1 || !slices.Equal(h.Active, []string{"incident aggregation"}) {
				t.Fatalf("corrupt evidence failure hidden: %+v", h)
			}
		})
	}
}
