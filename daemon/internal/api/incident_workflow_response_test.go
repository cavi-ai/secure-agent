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

func TestIncidentStatusFailureRollsBackAndRecovers(t *testing.T) {
	for _, failure := range []string{"read", "write"} {
		t.Run(failure, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "workflow.db")
			st, err := store.Open(path, "")
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if err := st.PutIncident(model.IncidentReport{ID: "incident", FlagID: "flag", Timestamp: time.Now()}); err != nil {
				t.Fatal(err)
			}
			if _, ok := st.AggregateIntoIncident("incident", "repeat", time.Now()); !ok {
				t.Fatal("could not aggregate repeat flag")
			}
			trigger := `CREATE TRIGGER fail_workflow AFTER UPDATE ON incidents BEGIN UPDATE incidents SET status=NULL WHERE id=NEW.id; END`
			if failure == "write" {
				trigger = `CREATE TRIGGER fail_workflow BEFORE UPDATE ON incidents BEGIN SELECT RAISE(ABORT, 'private-error-marker'); END`
			}
			if _, err := db.Exec(trigger); err != nil {
				t.Fatal(err)
			}
			a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
			post := func(payload string) *httptest.ResponseRecorder {
				t.Helper()
				w := httptest.NewRecorder()
				a.buildMux().ServeHTTP(w, httptest.NewRequest("POST", "/incidents/status", strings.NewReader(payload)))
				return w
			}
			w := post(`{"id":"repeat","status":"resolved","note":"reviewed"}`)
			if w.Code != 503 || strings.Contains(w.Body.String(), "private-error-marker") {
				t.Errorf("failed workflow must be unavailable without raw storage errors: %d %s", w.Code, w.Body.String())
			}
			var status string
			var ack, resolved, note sql.NullString
			if err := db.QueryRow(`SELECT status, acknowledged_at, resolved_at, resolution_note FROM incidents WHERE id='incident'`).Scan(&status, &ack, &resolved, &note); err != nil {
				t.Errorf("failed update left unreadable workflow: %v", err)
			} else if status != "open" || ack.Valid || resolved.Valid || note.Valid {
				t.Errorf("failed update was not rolled back: %q %+v %+v %+v", status, ack, resolved, note)
			}
			if audits := st.RecentAudit(10); len(audits) != 0 {
				t.Errorf("failed transition was audited as success: %+v", audits)
			}
			failed := st.WriteHealth()
			if failure == "read" && (failed.ReadFailures != 1 || len(failed.ReadActive) != 1 || failed.ReadActive[0] != "incident workflows") {
				t.Errorf("failed workflow read health: %+v", failed)
			}
			if _, err := db.Exec("DROP TRIGGER fail_workflow"); err != nil {
				t.Fatal(err)
			}
			w = post(`{"id":"repeat","status":"resolved","note":"reviewed"}`)
			if w.Code != 200 {
				t.Fatalf("recovery: %d %s", w.Code, w.Body.String())
			}
			var response struct {
				Status   string                 `json:"status"`
				Workflow store.IncidentWorkflow `json:"workflow"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response.Status != "ok" || response.Workflow.Status != "resolved" || response.Workflow.ResolvedAt == "" || response.Workflow.ResolutionNote != "reviewed" {
				t.Fatalf("recovery response: %+v", response)
			}
			persisted, found, err := st.IncidentStatusResult("incident")
			if err != nil || !found || persisted != response.Workflow {
				t.Errorf("response differs from committed workflow: %+v %v %v", persisted, found, err)
			}
			if audits := st.RecentAudit(10); len(audits) != 1 || audits[0].Action != "incident-status" || audits[0].ToMode != "resolved" {
				t.Errorf("recovery audit: %+v", audits)
			}
			health := st.WriteHealth()
			if health.ReadFailures != failed.ReadFailures || len(health.ReadActive) != 0 || len(health.Active) != 0 {
				t.Errorf("recovery health: %+v", health)
			}
			for _, tc := range []struct {
				payload string
				code    int
			}{
				{`{"id":"incident","status":"invalid"}`, 400},
				{`{"id":"missing","status":"resolved"}`, 404},
			} {
				if w := post(tc.payload); w.Code != tc.code {
					t.Errorf("%s: %d %s", tc.payload, w.Code, w.Body.String())
				}
			}
			if audits := st.RecentAudit(10); len(audits) != 1 {
				t.Errorf("invalid/missing update added audit: %+v", audits)
			}
		})
	}
}
