package api

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestSessionOutcomesRetainReceiptsWithoutReadingActivity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outcomes.db")
	st, err := store.Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	at := time.Now().UTC()
	for i, id := range []string{"owned", "other"} {
		pid := int32(40 + i)
		if err := st.UpsertSession(model.Session{ID: id, Harness: "claude", RootPID: pid, RootStartedAt: at.Format(time.RFC3339Nano), Status: model.SessionEnded, StartedAt: at, LastSeenAt: at}); err != nil {
			t.Fatal(err)
		}
		f := model.Flag{ID: id + "-flag", SessionID: id, Rule: "sensitive-read-then-connect", TS: at, Severity: 3}
		if _, err := st.PutFlag(f); err != nil {
			t.Fatal(err)
		}
		r, err := st.ObserveFindingReview(f, model.AssessFinding(f))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.DecideFindingReview(model.ReviewDecisionRequest{ID: r.ID, Revision: r.Revision, Action: "acknowledge"}); err != nil {
			t.Fatal(err)
		}
		control := model.InterventionReceipt{ID: id + "-control", RootPID: pid, RootStartedAt: at, SessionKey: id, Revision: 1, RequestedAt: at, Status: "requested", Kind: "pause", Verification: "unknown"}
		if ok, err := st.ReserveIntervention(control); err != nil || !ok {
			t.Fatalf("reserve control: %v %v", ok, err)
		}
		control.Revision, control.Status, control.Verification = 2, "failed", "unknown"
		if err := st.SaveIntervention(control); err != nil {
			t.Fatal(err)
		}
		inc := model.IncidentReport{ID: id + "-incident", SessionID: id, Timestamp: at, RotateList: []model.RotateItem{{ID: "key", Name: "Synthetic key", Action: "Revoke affected key"}}}
		if err := st.PutIncident(inc); err != nil {
			t.Fatal(err)
		}
		stored, err := st.GetIncident(inc.ID)
		if err != nil {
			t.Fatal(err)
		}
		view := stored.Remediation
		if _, err := st.ReportIncidentRemediation(model.IncidentRemediationRequest{ID: inc.ID, StepID: view.Steps[0].ID, ExpectedRevision: view.Revision, ExpectedEvidence: view.EvidenceRevision, Status: "reported"}); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Receipt reads must remain useful when unrelated activity storage fails.
	if _, err := db.Exec(`ALTER TABLE events RENAME TO unavailable_events`); err != nil {
		t.Fatal(err)
	}
	mux := newTestAPI("", st, nil, nil).buildMux()
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/sessions/owned/outcomes", nil))
	if w.Code != 200 {
		t.Fatalf("outcomes: %d %s", w.Code, w.Body.String())
	}
	var out SessionOutcomes
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.SessionID != "owned" || len(out.History.Incidents) != 1 || out.History.Incidents[0].ID != "owned-incident" || out.History.Incidents[0].Remediation.Steps[0].Status != "reported" {
		t.Fatalf("lost receipt or crossed session boundary: %+v", out)
	}
	if len(out.History.Reviews) != 1 || out.History.Reviews[0].Decision == nil || out.History.Reviews[0].Context.SessionID != "owned" || out.History.Reviews[0].AvailableScopes != nil {
		t.Fatalf("missing, actionable, or cross-session review: %+v", out.History.Reviews)
	}
	if len(out.History.Interventions) != 1 || out.History.Interventions[0].ID != "owned-control" || out.History.Interventions[0].Status != "failed" {
		t.Fatalf("lost or cross-session process result: %+v", out.History.Interventions)
	}
	var originalReceipt string
	if err := db.QueryRow(`SELECT receipt_json FROM interventions WHERE id='owned-control'`).Scan(&originalReceipt); err != nil {
		t.Fatal(err)
	}
	for _, damage := range []string{`'null'`, `json_set(receipt_json,'$.session_id','other')`, `json_set(receipt_json,'$.revision',99)`} {
		if _, err := db.Exec(`UPDATE interventions SET receipt_json=` + damage + ` WHERE id='owned-control'`); err != nil {
			t.Fatal(err)
		}
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", "/sessions/owned/outcomes", nil))
		if w.Code != 200 {
			t.Fatalf("corrupt receipt outcomes: %d", w.Code)
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out.History.Evidence.Interventions.Available || len(out.History.Interventions) != 0 || !out.History.Evidence.Incidents.Available || len(out.History.Incidents) != 1 || !out.History.Evidence.Reviews.Available || len(out.History.Reviews) != 1 {
			t.Fatalf("corrupt receipt escaped or erased readable siblings: %+v", out)
		}
		if _, err := db.Exec(`UPDATE interventions SET receipt_json=? WHERE id='owned-control'`, originalReceipt); err != nil {
			t.Fatal(err)
		}
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", "/sessions/owned/outcomes", nil))
		if w.Code != 200 {
			t.Fatalf("recovered receipt outcomes: %d", w.Code)
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if !out.History.Evidence.Interventions.Available || len(out.History.Interventions) != 1 || out.History.Interventions[0].ID != "owned-control" {
			t.Fatalf("receipt recovery: %+v", out)
		}
	}
	var originalIncident string
	if err := db.QueryRow(`SELECT report_json FROM incidents WHERE id='owned-incident'`).Scan(&originalIncident); err != nil {
		t.Fatal(err)
	}
	for _, damage := range []string{`json_set(report_json,'$.session_id','other')`, `json_remove(report_json,'$.session_id')`, `json_set(report_json,'$.session_id',NULL)`} {
		if _, err := db.Exec(`UPDATE incidents SET report_json=` + damage + ` WHERE id='owned-incident'`); err != nil {
			t.Fatal(err)
		}
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", "/sessions/owned/outcomes", nil))
		if w.Code != 200 {
			t.Fatalf("corrupt incident outcomes: %d", w.Code)
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out.History.Evidence.Incidents.Available || len(out.History.Incidents) != 0 || !out.History.Evidence.Interventions.Available || len(out.History.Interventions) != 1 || !out.History.Evidence.Reviews.Available || len(out.History.Reviews) != 1 {
			t.Fatalf("mismatched incident escaped or erased readable siblings: %+v", out)
		}
		if _, err := db.Exec(`UPDATE incidents SET report_json=? WHERE id='owned-incident'`, originalIncident); err != nil {
			t.Fatal(err)
		}
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", "/sessions/owned/outcomes", nil))
		if w.Code != 200 {
			t.Fatalf("recovered incident outcomes: %d", w.Code)
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if !out.History.Evidence.Incidents.Available || len(out.History.Incidents) != 1 || out.History.Incidents[0].ID != "owned-incident" || out.History.Incidents[0].Remediation.Steps[0].Status != "reported" {
			t.Fatalf("incident recovery lost saved remediation: %+v", out)
		}
	}
	if _, err := db.Exec(`ALTER TABLE interventions RENAME TO unavailable_interventions`); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/sessions/owned/outcomes", nil))
	if w.Code != 200 {
		t.Fatalf("partial outcomes: %d", w.Code)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.History.Evidence.Interventions.Available || !out.History.Evidence.Incidents.Available || len(out.History.Incidents) != 1 {
		t.Fatalf("source failure erased readable receipts: %+v", out)
	}
}

func TestSessionOutcomesIdentityErrors(t *testing.T) {
	st := testStore(t)
	mux := newTestAPI("", st, nil, nil).buildMux()
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/sessions/missing/outcomes", nil))
	if w.Code != 404 {
		t.Fatalf("missing session: %d", w.Code)
	}
	st.Close()
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/sessions/missing/outcomes", nil))
	if w.Code != 503 {
		t.Fatalf("unavailable session became missing: %d", w.Code)
	}
}
