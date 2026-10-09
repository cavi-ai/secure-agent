package store

import (
	"database/sql"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestIncidentReadResultsDiscardPartialRowsAndRecover(t *testing.T) {
	for _, payload := range []any{nil, "invalid", "null", "{}", `{"id":"other"}`, `{"id":"bad","timestamp":"invalid"}`} {
		t.Run("report", func(t *testing.T) {
			s, err := Open("", "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			bad := model.IncidentReport{ID: "bad", FlagID: "flag-bad", Timestamp: time.Now()}
			for _, report := range []model.IncidentReport{bad, {ID: "good", Timestamp: time.Now()}} {
				if err := s.PutIncident(report); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.db.Exec("UPDATE incidents SET report_json=? WHERE id='bad'", payload); err != nil {
				t.Fatal(err)
			}
			got, err := s.RecentIncidentsResult(10)
			if err == nil || got != nil {
				t.Fatalf("partial incidents: %+v, %v", got, err)
			}
			if got, err := s.GetIncident("flag-bad"); err == nil || got != nil {
				t.Fatalf("corrupt detail: %+v, %v", got, err)
			}
			h := s.WriteHealth()
			if h.ReadFailures != 2 || !slices.Equal(h.ReadActive, []string{"incidents"}) || h.Failures != 0 {
				t.Fatalf("read failure health: %+v", h)
			}
			if err := s.PutIncident(bad); err != nil {
				t.Fatal(err)
			}
			got, err = s.RecentIncidentsResult(10)
			if err != nil || len(got) != 2 {
				t.Fatalf("read recovery: %+v, %v", got, err)
			}
			h = s.WriteHealth()
			if h.ReadFailures != 2 || len(h.ReadActive) != 0 {
				t.Fatalf("recovery health: %+v", h)
			}
			if _, err := s.GetIncident("missing"); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("missing incident: %v", err)
			}
			if h := s.WriteHealth(); h.ReadFailures != 2 || len(h.ReadActive) != 0 {
				t.Fatalf("absence recorded as failure: %+v", h)
			}
		})
	}
}

func TestIncidentReadQueryFailure(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if got, err := s.RecentIncidentsResult(10); err == nil || got != nil {
		t.Fatalf("closed history: %+v, %v", got, err)
	}
	if got, err := s.GetIncident("missing"); err == nil || errors.Is(err, sql.ErrNoRows) || got != nil {
		t.Fatalf("closed detail: %+v, %v", got, err)
	}
	if _, found, err := s.IncidentStatusResult("missing"); err == nil || found {
		t.Fatalf("closed workflow: found=%v, %v", found, err)
	}
	if h := s.WriteHealth(); h.ReadFailures != 3 || !slices.Equal(h.ReadActive, []string{"incident workflows", "incidents"}) || h.Failures != 0 {
		t.Fatalf("closed read health: %+v", h)
	}
}

func TestIncidentWorkflowReadRecoveryAndNullableFields(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.PutIncident(model.IncidentReport{ID: "incident", FlagID: "flag", Timestamp: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE incidents SET status=NULL WHERE id='incident'"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.RecentIncidentsResult(10); err != nil || len(got) != 1 {
		t.Fatalf("NULL workflow hid report: %+v, %v", got, err)
	}
	if _, found, err := s.IncidentStatusResult("flag"); found || err == nil {
		t.Fatalf("NULL workflow: found=%v err=%v", found, err)
	}
	if h := s.WriteHealth(); h.ReadFailures != 1 || !slices.Equal(h.ReadActive, []string{"incident workflows"}) {
		t.Fatalf("workflow health: %+v", h)
	}
	if _, err := s.db.Exec("UPDATE incidents SET status='open', acknowledged_at=NULL, resolved_at=NULL, resolution_note=NULL WHERE id='incident'"); err != nil {
		t.Fatal(err)
	}
	wf, found, err := s.IncidentStatusResult("flag")
	if err != nil || !found || wf != (IncidentWorkflow{Status: "open"}) {
		t.Fatalf("nullable workflow recovery: %+v, %v, %v", wf, found, err)
	}
	if _, found, err := s.IncidentStatusResult("missing"); err != nil || found {
		t.Fatalf("missing workflow: found=%v err=%v", found, err)
	}
	if h := s.WriteHealth(); h.ReadFailures != 1 || len(h.ReadActive) != 0 {
		t.Fatalf("workflow recovery health: %+v", h)
	}
	if _, err := s.SetIncidentStatus("incident", "resolved", ""); err != nil {
		t.Fatal(err)
	}
	if got, err := s.RecentIncidentsResult(10); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("resolved active history: %+v, %v", got, err)
	}
	if got, err := s.GetIncident("flag"); err != nil || got.ID != "incident" {
		t.Fatalf("resolved detail disappeared: %+v, %v", got, err)
	}
}

func TestIncidentCursorFailureDiscardsEarlierValidRows(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, id := range []string{"bad", "good"} {
		if err := s.PutIncident(model.IncidentReport{ID: id, Timestamp: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	q := strings.Replace(recentIncidentsQuery, "report_json", "CASE WHEN id='bad' THEN json_extract('invalid','$') ELSE report_json END", 1)
	q = strings.Replace(q, "ORDER BY datetime(created_at) DESC, created_at DESC", "ORDER BY rowid DESC", 1)
	rows, err := s.db.Query(q, 10)
	if err != nil {
		t.Fatal(err)
	}
	got, err := scanIncidentsResult(rows)
	if err == nil || got != nil {
		t.Fatalf("cursor returned partial reports: %+v, %v", got, err)
	}
}
