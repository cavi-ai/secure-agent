package api

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestIncidentRemediationReportsRemainUnverifiedAndRevisionBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	st, err := store.Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	st.UpsertSession(model.Session{ID: "session", Harness: "claude", StartedAt: now, LastSeenAt: now})
	inc := model.IncidentReport{ID: "incident", FlagID: "flag", Timestamp: time.Now(), SessionID: "session", RotateList: []model.RotateItem{
		{ID: "rot-env-.env", Name: "Environment file", Path: "/workspace/one/.env", Action: "Rotate affected keys"},
		{ID: "rot-env-.env", Name: "Environment file", Path: "/workspace/two/.env", Action: "Rotate affected keys"},
	}}
	if err := st.PutIncident(inc); err != nil {
		t.Fatal(err)
	}
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	get := func() map[string]any {
		t.Helper()
		w := httptest.NewRecorder()
		a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/incidents?id=incident", nil))
		if w.Code != 200 {
			t.Fatalf("read: %d %s", w.Code, w.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	post := func(payload map[string]any) *httptest.ResponseRecorder {
		t.Helper()
		raw, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		a.buildMux().ServeHTTP(w, httptest.NewRequest("POST", "/incidents/remediation", strings.NewReader(string(raw))))
		return w
	}
	before := get()
	rem, ok := before["incident"].(map[string]any)["remediation"].(map[string]any)
	if !ok {
		t.Fatal("incident has no actionable remediation projection")
	}
	steps := rem["steps"].([]any)
	first, second := steps[0].(map[string]any), steps[1].(map[string]any)
	if first["id"] == second["id"] {
		t.Fatal("same basename transferred remediation between paths")
	}
	req := map[string]any{"id": "incident", "step_id": first["id"], "expected_revision": rem["revision"], "expected_evidence": rem["evidence_revision"], "status": "reported"}
	if w := post(req); w.Code != 200 {
		t.Fatalf("report: %d %s", w.Code, w.Body.String())
	}
	after := get()
	if after["workflow"].(map[string]any)["status"] != "open" {
		t.Fatal("reporting a step resolved the incident")
	}
	rem = after["incident"].(map[string]any)["remediation"].(map[string]any)
	steps = rem["steps"].([]any)
	first, second = steps[0].(map[string]any), steps[1].(map[string]any)
	if first["status"] != "reported" || first["verification"] != "unverified" || first["reported_at"] == nil || second["status"] != "pending" {
		t.Fatalf("untruthful or cross-item result: %+v", rem)
	}
	report, found := st.SessionReport("session")
	if !found || !report.IncidentsAvailable || len(report.Incidents) != 1 {
		t.Fatalf("missing session export: %+v", report)
	}
	md := renderSessionMarkdown(report)
	if !strings.Contains(md, "reported completed · credential verification: unverified") {
		t.Fatalf("untruthful export: %s", md)
	}
	w := httptest.NewRecorder()
	a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/incidents?id=incident&format=markdown", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Reported completed · Unverified") {
		t.Fatalf("incident export: %d %s", w.Code, w.Body.String())
	}
	if w := post(req); w.Code != 409 {
		t.Fatalf("stale revision accepted: %d", w.Code)
	}
	req["expected_revision"], req["expected_evidence"] = rem["revision"], rem["evidence_revision"]
	if _, ok := st.AggregateIntoIncident("incident", "later-flag", time.Now().Add(time.Second)); !ok {
		t.Fatal("aggregate")
	}
	if w := post(req); w.Code != 409 {
		t.Fatalf("stale evidence accepted: %d", w.Code)
	}
	rem = get()["incident"].(map[string]any)["remediation"].(map[string]any)
	if rem["steps"].([]any)[0].(map[string]any)["newer_evidence"] != true {
		t.Fatal("later evidence hidden by earlier report")
	}
	req["expected_evidence"] = rem["evidence_revision"]
	req["status"] = "verified"
	if w := post(req); w.Code != 400 {
		t.Fatalf("caller invented verification: %d", w.Code)
	}
	req["status"] = "pending"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER fail_remediation BEFORE UPDATE ON incidents BEGIN SELECT RAISE(ABORT, 'private-failure'); END`); err != nil {
		t.Fatal(err)
	}
	if w := post(req); w.Code != 503 || strings.Contains(w.Body.String(), "private-failure") {
		t.Fatalf("storage failure: %d %s", w.Code, w.Body.String())
	}
	if get()["incident"].(map[string]any)["remediation"].(map[string]any)["revision"] != rem["revision"] {
		t.Fatal("failed write changed revision")
	}
}
