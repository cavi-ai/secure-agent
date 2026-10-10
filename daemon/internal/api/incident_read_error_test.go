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

func TestIncidentReadResolvesAggregatedFlags(t *testing.T) {
	st := testStore(t)
	now := time.Now()
	if err := st.PutIncident(model.IncidentReport{ID: "incident", FlagID: "first", Timestamp: now, Summary: "Aggregated report"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.AggregateIntoIncident("incident", "second", now); !ok {
		t.Fatal("could not aggregate second flag")
	}
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	for _, id := range []string{"incident", "first", "second"} {
		w := httptest.NewRecorder()
		a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/incidents?id="+id, nil))
		if w.Code != 200 {
			t.Errorf("lookup %s: %d %s", id, w.Code, w.Body.String())
			continue
		}
		var got struct {
			Incident model.IncidentReport `json:"incident"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Incident.ID != "incident" || got.Incident.AggregateCount != 2 {
			t.Errorf("lookup %s returned wrong report: %+v", id, got.Incident)
		}
	}
	// A report identity takes priority over an older report's flag alias.
	if err := st.PutIncident(model.IncidentReport{ID: "first", FlagID: "other-flag", Timestamp: now}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/incidents?id=first", nil))
	var got struct {
		Incident model.IncidentReport `json:"incident"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("report identity lookup: %d %s", w.Code, w.Body.String())
	}
	if w.Code != 200 || got.Incident.ID != "first" {
		t.Fatalf("report identity lost to flag alias: %d %+v", w.Code, got.Incident)
	}
}

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
			var savedReport string
			if err := db.QueryRow("SELECT report_json FROM incidents WHERE id='bad'").Scan(&savedReport); err != nil {
				t.Fatal(err)
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
			if _, err := db.Exec("UPDATE incidents SET report_json=? WHERE id='bad'", savedReport); err != nil {
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
