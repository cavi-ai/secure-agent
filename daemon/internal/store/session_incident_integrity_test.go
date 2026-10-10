package store

import (
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestSessionIncidentsRejectMismatchedSessionAndRecover(t *testing.T) {
	for _, damage := range []string{
		`json_set(report_json,'$.session_id','other')`,
		`json_remove(report_json,'$.session_id')`,
		`json_set(report_json,'$.session_id',NULL)`,
	} {
		t.Run(damage, func(t *testing.T) {
			s, err := Open("", "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			now := time.Now().UTC()
			for i, id := range []string{"bad", "good"} {
				if err := s.PutIncident(model.IncidentReport{ID: id, SessionID: "owned", Timestamp: now.Add(time.Duration(i) * time.Second)}); err != nil {
					t.Fatal(err)
				}
			}
			var original string
			if err := s.db.QueryRow("SELECT report_json FROM incidents WHERE id='bad'").Scan(&original); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec("UPDATE incidents SET report_json=" + damage + " WHERE id='bad'"); err != nil {
				t.Fatal(err)
			}
			if got, err := s.SessionIncidents("owned"); err == nil || got != nil {
				t.Errorf("mismatched session returned successful or partial history: count=%d err=%v", len(got), err)
			}
			if h := s.WriteHealth(); h.ReadFailures != 1 || !slices.Equal(h.ReadActive, []string{"incident remediation"}) || h.Failures != 0 {
				t.Errorf("incident attribution failure hidden: %+v", h)
			}
			if _, err := s.db.Exec("UPDATE incidents SET report_json=? WHERE id='bad'", original); err != nil {
				t.Fatal(err)
			}
			got, err := s.SessionIncidents("owned")
			if err != nil || len(got) != 2 || got[0].ID != "good" || got[1].ID != "bad" || got[0].Remediation == nil || got[1].Remediation == nil {
				t.Fatalf("incident history did not recover: %+v %v", got, err)
			}
			if h := s.WriteHealth(); h.ReadFailures != 1 || len(h.ReadActive) != 0 {
				t.Errorf("incident attribution read health did not recover: %+v", h)
			}
		})
	}
}
