package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestSessionReportReadFailuresRejectReportsAndPlans(t *testing.T) {
	for _, tc := range []struct{ name, damage, repair string }{
		{"session", `UPDATE sessions SET started_at='invalid' WHERE id='s1'`, ""},
		{"event scan", `UPDATE events SET duration_ms='invalid' WHERE detail='bad'`, `UPDATE events SET duration_ms=0`},
		{"event timestamp", `UPDATE events SET ts='invalid' WHERE detail='bad'`, ""},
		{"event query", `ALTER TABLE events RENAME TO unavailable_events`, `ALTER TABLE unavailable_events RENAME TO events`},
		{"flag", `UPDATE flags SET evidence='invalid' WHERE id='f1'`, `UPDATE flags SET evidence=NULL WHERE id='f1'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "report.db")
			st, err := store.Open(path, "")
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			now := time.Now().UTC()
			st.UpsertSession(model.Session{ID: "s1", Harness: "codex", Status: model.SessionActive, Confidence: model.ConfHook, StartedAt: now.Add(-time.Hour), LastSeenAt: now})
			for i, detail := range []string{"good", "bad"} {
				if _, err := st.PutEvent(event.Event{Kind: event.KindTurn, TS: now.Add(time.Duration(i) * time.Second), SessionID: "s1", Detail: detail}); err != nil {
					t.Fatal(err)
				}
			}
			if events, err := st.QueryEventsResult(store.EventFilter{SessionID: "s1"}); err != nil || len(events) != 2 {
				t.Fatalf("two-event fixture: %d events, %v", len(events), err)
			}
			if _, err := st.PutFlag(model.Flag{ID: "f1", Rule: "rule", TS: now, SessionID: "s1"}); err != nil {
				t.Fatal(err)
			}
			if err := st.PutIncident(model.IncidentReport{ID: "i1", Rule: "rule", SessionID: "s1", Timestamp: now}); err != nil {
				t.Fatal(err)
			}
			a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
			rec := &planRecorder{ready: true, pending: map[string]bool{}}
			a.plan = rec.funcs()
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec(tc.damage); err != nil {
				t.Fatal(err)
			}
			for _, format := range []string{"json", "md"} {
				w := httptest.NewRecorder()
				a.serveSessionReport(w, httptest.NewRequest(http.MethodGet, "/sessions/s1/report?format="+format, nil), "s1")
				if tc.name == "session" {
					if w.Code != http.StatusServiceUnavailable {
						t.Errorf("%s unavailable identity: %d %s", format, w.Code, w.Body.String())
					}
					continue
				}
				if w.Code != http.StatusOK || w.Header().Get("X-Secure-Agent-Report-State") != "partial" {
					t.Fatalf("%s unavailable source: %d %s", format, w.Code, w.Body.String())
				}
				if format == "json" {
					var rep store.SessionReport
					if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
						t.Fatal(err)
					}
					if rep.Evidence == nil {
						t.Fatal("missing source availability")
					}
					if tc.name == "flag" {
						if rep.Evidence.Flags.Available || len(rep.Flags) != 0 || rep.Events != 2 {
							t.Fatalf("partial flags or lost activity: %+v", rep)
						}
					} else if rep.Evidence.Events.Available || rep.Events != 0 || len(rep.Timeline) != 0 || len(rep.Flags) != 1 {
						t.Fatalf("partial activity or lost flags: %+v", rep)
					}
				}
			}
			if code, _ := planCall(t, a, http.MethodPost, "incident:i1"); code != http.StatusServiceUnavailable {
				t.Errorf("plan from failed report: %d", code)
			}
			if len(rec.reqs) != 0 {
				t.Errorf("enqueued %d plans from failed report", len(rec.reqs))
			}
			if tc.repair != "" {
				if _, err := db.Exec(tc.repair); err != nil {
					t.Fatal(err)
				}
			} else if tc.name == "session" {
				if _, err := db.Exec("UPDATE sessions SET started_at=? WHERE id='s1'", now.Add(-time.Hour).Format(time.RFC3339Nano)); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := db.Exec("UPDATE events SET ts=? WHERE detail='bad'", now.Add(time.Second).Format(time.RFC3339Nano)); err != nil {
					t.Fatal(err)
				}
			}
			w := httptest.NewRecorder()
			a.serveSessionReport(w, httptest.NewRequest(http.MethodGet, "/sessions/s1/report", nil), "s1")
			if w.Code != http.StatusOK {
				t.Fatalf("recovered report: %d %s", w.Code, w.Body.String())
			}
			if code, _ := planCall(t, a, http.MethodPost, "incident:i1"); code != http.StatusAccepted || len(rec.reqs) != 1 {
				t.Fatalf("recovered plan: %d requests=%d", code, len(rec.reqs))
			}
		})
	}
}
