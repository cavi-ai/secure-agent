package api

import (
	"database/sql"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestIncidentReadFailuresRejectPartialResponsesAndRecover(t *testing.T) {
	for _, payload := range []string{"invalid", "null", "{}", `{"id":"other"}`, `{"id":"bad","timestamp":"invalid"}`} {
		t.Run(payload, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "incidents.db")
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
			bad := model.IncidentReport{ID: "bad", FlagID: "flag-bad", Timestamp: time.Now()}
			for _, report := range []model.IncidentReport{bad, {ID: "good", Timestamp: time.Now()}} {
				if err := st.PutIncident(report); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := db.Exec("UPDATE incidents SET report_json=? WHERE id='bad'", payload); err != nil {
				t.Fatal(err)
			}
			a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
			for _, url := range []string{"/incidents", "/incidents?id=bad", "/incidents?id=flag-bad&format=md", "/snapshot"} {
				w := httptest.NewRecorder()
				a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", url, nil))
				if w.Code != 503 {
					t.Errorf("%s hides failed incident read: %d %s", url, w.Code, w.Body.String())
				}
			}
			if err := st.PutIncident(bad); err != nil {
				t.Fatal(err)
			}
			for _, url := range []string{"/incidents", "/incidents?id=bad", "/incidents?id=flag-bad&format=md", "/snapshot"} {
				w := httptest.NewRecorder()
				a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", url, nil))
				if w.Code != 200 {
					t.Errorf("%s did not recover: %d %s", url, w.Code, w.Body.String())
				}
			}
		})
	}
}

func TestIncidentReadDistinguishesMissingFromUnavailable(t *testing.T) {
	st := testStore(t)
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	w := httptest.NewRecorder()
	a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/incidents?id=missing", nil))
	if w.Code != 404 {
		t.Fatalf("missing incident: %d", w.Code)
	}
	st.Close()
	for _, url := range []string{"/incidents", "/incidents?id=missing", "/incidents?id=missing&format=md"} {
		w := httptest.NewRecorder()
		a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", url, nil))
		if w.Code != 503 {
			t.Errorf("%s hides query failure: %d %s", url, w.Code, w.Body.String())
		}
	}
}

func TestIncidentReadRejectsUnavailableWorkflow(t *testing.T) {
	for _, status := range []any{nil, "", "invalid"} {
		t.Run("status", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "incidents.db")
			st, err := store.Open(path, "")
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			if err := st.PutIncident(model.IncidentReport{ID: "bad", Timestamp: time.Now()}); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec("UPDATE incidents SET status=? WHERE id='bad'", status); err != nil {
				t.Fatal(err)
			}
			a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
			for _, url := range []string{"/incidents", "/incidents?id=bad", "/snapshot"} {
				w := httptest.NewRecorder()
				a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", url, nil))
				if w.Code != 503 {
					t.Errorf("%s hides unavailable workflow: %d %s", url, w.Code, w.Body.String())
				}
			}
		})
	}
}
