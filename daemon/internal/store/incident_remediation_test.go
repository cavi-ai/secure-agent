package store

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestIncidentAggregationReplayRetainsRemediation(t *testing.T) {
	st, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now()
	inc := model.IncidentReport{ID: "incident", FlagID: "first", Timestamp: now, RotateList: []model.RotateItem{{ID: "key", Name: "Key", Action: "Revoke affected key"}}}
	if err := st.PutIncident(inc); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.AggregateIntoIncident(inc.ID, "second", now.Add(time.Second)); !ok {
		t.Fatal("could not aggregate second flag")
	}
	before, err := st.GetIncident(inc.ID)
	if err != nil {
		t.Fatal(err)
	}
	view := before.Remediation
	saved, err := st.ReportIncidentRemediation(model.IncidentRemediationRequest{ID: inc.ID, StepID: view.Steps[0].ID, ExpectedRevision: view.Revision, ExpectedEvidence: view.EvidenceRevision, Status: "reported"})
	if err != nil {
		t.Fatal(err)
	}
	for _, flagID := range []string{"first", "second"} {
		replayed, ok := st.AggregateIntoIncident(inc.ID, flagID, now.Add(time.Hour))
		if !ok || replayed.AggregateCount != 2 || replayed.LastFlagAt == nil || !replayed.LastFlagAt.Equal(now.Add(time.Second)) {
			t.Fatalf("replay changed evidence: %+v ok=%v", replayed, ok)
		}
		if !reflect.DeepEqual(replayed.Remediation, saved.Remediation) {
			t.Errorf("replay lost saved remediation: got=%+v want=%+v", replayed.Remediation, saved.Remediation)
		}
	}
	// Unreadable bookkeeping must not escape as a successful empty view.
	if _, err := st.db.Exec(`UPDATE incidents SET remediation_json='null' WHERE id=?`, inc.ID); err != nil {
		t.Fatal(err)
	}
	if report, ok := st.AggregateIntoIncident(inc.ID, "second", now); ok || report.ID != "" {
		t.Fatal("replay hid unreadable remediation")
	}
	if h := st.WriteHealth(); h.ReadFailures != 1 || len(h.ReadActive) != 1 || h.ReadActive[0] != "incidents" {
		t.Errorf("replay read fault hidden: %+v", h)
	}
	if _, err := st.db.Exec(`UPDATE incidents SET remediation_json='' WHERE id=?`, inc.ID); err != nil {
		t.Fatal(err)
	}
	if report, ok := st.AggregateIntoIncident(inc.ID, "second", now); !ok || report.Remediation == nil || report.Remediation.Steps[0].Status != "pending" {
		t.Fatalf("replay did not recover: %+v ok=%v", report, ok)
	}
	if h := st.WriteHealth(); h.ReadFailures != 1 || len(h.ReadActive) != 0 {
		t.Errorf("replay health did not recover: %+v", h)
	}
}

func mustJSONForRemediationTest(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestIncidentRemediationSurvivesReopenAndDoesNotTransferToChangedStep(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	st, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	inc := model.IncidentReport{ID: "incident", FlagID: "flag", SessionID: "owned", Timestamp: time.Now(), RotateList: []model.RotateItem{{ID: "key", Name: "Key", Path: "/one/key", Action: "Revoke affected key"}}}
	if err := st.PutIncident(inc); err != nil {
		t.Fatal(err)
	}
	before, err := st.GetIncident(inc.ID)
	if err != nil {
		t.Fatal(err)
	}
	view := before.Remediation
	if _, err := st.ReportIncidentRemediation(model.IncidentRemediationRequest{ID: inc.ID, StepID: view.Steps[0].ID, ExpectedRevision: view.Revision, ExpectedEvidence: view.EvidenceRevision, Status: "reported"}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	st, err = Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	incidents, err := st.SessionIncidents("owned")
	if err != nil || len(incidents) != 1 || incidents[0].Remediation.Steps[0].Status != "reported" {
		t.Fatalf("lost durable report: %+v %v", incidents, err)
	}
	if other, err := st.SessionIncidents("unrelated"); err != nil || len(other) != 0 {
		t.Fatalf("cross-session report: %+v %v", other, err)
	}
	st.UpsertSession(model.Session{ID: "owned", Harness: "claude", StartedAt: inc.Timestamp, LastSeenAt: inc.Timestamp})
	st.UpsertSession(model.Session{ID: "canonical", Harness: "claude", StartedAt: inc.Timestamp, LastSeenAt: inc.Timestamp})
	if err := st.RekeySession("owned", "canonical"); err != nil {
		t.Fatal(err)
	}
	if rows, err := st.SessionIncidents("owned"); err != nil || len(rows) != 0 {
		t.Fatalf("old identity retained report: %+v %v", rows, err)
	}
	if rows, err := st.SessionIncidents("canonical"); err != nil || len(rows) != 1 || rows[0].Remediation.Steps[0].Status != "reported" {
		t.Fatalf("rekey lost report: %+v %v", rows, err)
	}
	inc.SessionID = "canonical"
	inc.RotateList[0].Action = "Review a different credential action"
	raw := mustJSONForRemediationTest(t, inc)
	if _, err := st.db.Exec(`UPDATE incidents SET report_json=? WHERE id=?`, raw, inc.ID); err != nil {
		t.Fatal(err)
	}
	after, err := st.GetIncident(inc.ID)
	if err != nil || after.Remediation.Steps[0].Status != "pending" {
		t.Fatalf("completion transferred to changed action: %+v %v", after, err)
	}
	inc.RotateList[0].Action = ""
	if _, err := st.db.Exec(`UPDATE incidents SET report_json=? WHERE id=?`, mustJSONForRemediationTest(t, inc), inc.ID); err != nil {
		t.Fatal(err)
	}
	if legacy, err := st.GetIncident(inc.ID); err != nil || len(legacy.Remediation.Steps) != 0 {
		t.Fatalf("incomplete advice became actionable: %+v %v", legacy, err)
	}
	if _, err := st.db.Exec(`UPDATE incidents SET remediation_json='null' WHERE id=?`, inc.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetIncident(inc.ID); err == nil {
		t.Fatal("corrupt report became no remediation")
	}
}
