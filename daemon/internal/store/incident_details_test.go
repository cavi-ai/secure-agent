package store

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestIncidentDetailsOwnWorkflowAndAliasIdentity(t *testing.T) {
	s := reviewStore(t)
	for _, report := range []model.IncidentReport{
		{ID: "canonical", FlagID: "alias", SessionID: "session", Timestamp: time.Now()},
		{ID: "alias", FlagID: "other", SessionID: "session", Timestamp: time.Now()},
	} {
		if err := s.PutIncident(report); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.SetIncidentStatusResult("canonical", "acknowledged", "reviewed"); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetIncidentDetail("alias")
	if err != nil || got.ID != "alias" || got.Workflow.Status != "open" {
		t.Fatalf("exact identity: %+v %v", got, err)
	}
	got, err = s.GetIncidentDetail("other")
	if err != nil || got.ID != "alias" {
		t.Fatalf("alias identity: %+v %v", got, err)
	}
	if _, err := s.GetIncidentDetail("missing"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("absence: %v", err)
	}
	rows, err := s.RecentIncidentDetails(10)
	if err != nil || len(rows) != 2 {
		t.Fatalf("history: %+v %v", rows, err)
	}
	for _, row := range rows {
		if row.ID == "canonical" && (row.Workflow.Status != "acknowledged" || row.Workflow.AcknowledgedAt == "") {
			t.Fatalf("workflow: %+v", row)
		}
	}
	if _, err := s.db.Exec("UPDATE incidents SET status=NULL WHERE id='canonical'"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.RecentIncidentDetails(10); err == nil || got != nil {
		t.Fatalf("partial details: %+v %v", got, err)
	}
	if got, err := s.SessionIncidentDetails("session"); err == nil || got != nil {
		t.Fatalf("partial session details: %+v %v", got, err)
	}
	if _, err := s.db.Exec("UPDATE incidents SET status='acknowledged' WHERE id='canonical'"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.RecentIncidentDetails(10); err != nil || len(got) != 2 {
		t.Fatalf("recovery: %+v %v", got, err)
	}
}
