package store

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

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
