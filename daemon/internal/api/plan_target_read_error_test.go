package api

import (
	"database/sql"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestPlanTargetReadFailuresRejectDecisionsAndRecover(t *testing.T) {
	for _, tc := range []struct{ subject, damage, repair string }{
		{"flag:f1", `UPDATE flags SET pid='invalid' WHERE id='f1'`, `UPDATE flags SET pid=1 WHERE id='f1'`},
		{"flag:f1", `UPDATE flags SET evidence='invalid' WHERE id='f1'`, `UPDATE flags SET evidence='null' WHERE id='f1'`},
		{"incident:i1", `UPDATE incidents SET report_json='invalid' WHERE id='i1'`, ""},
		{"incident:i1", `UPDATE flags SET evidence='invalid' WHERE id='f1'`, `UPDATE flags SET evidence='null' WHERE id='f1'`},
	} {
		t.Run(tc.subject+tc.damage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "targets.db")
			st, err := store.Open(path, "")
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			if _, err := st.PutFlag(model.Flag{ID: "f1", Rule: "secret-in-transcript", Agent: "codex", PID: 1, TS: time.Now(), Severity: 3}); err != nil {
				t.Fatal(err)
			}
			inc := model.IncidentReport{ID: "i1", FlagID: "f1", Rule: "secret-in-transcript", Agent: "codex", Timestamp: time.Now()}
			if err := st.PutIncident(inc); err != nil {
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
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				if code, _ := planCall(t, a, method, tc.subject); code != http.StatusServiceUnavailable {
					t.Errorf("%s failed target: %d, want 503", method, code)
				}
			}
			body := map[string]string{"subject": tc.subject, "label": "ok"}
			if w := postJSON(a.handleLabels, "/labels", body); w.Code != http.StatusServiceUnavailable {
				t.Errorf("label on failed target: %d %s", w.Code, w.Body.String())
			}
			if len(rec.reqs) != 0 {
				t.Errorf("enqueued %d plans from failed target", len(rec.reqs))
			}
			if labels := st.SimilarLabels("secret-in-transcript", "codex", "", 5); len(labels) != 0 {
				t.Errorf("recorded judgments from failed target: %+v", labels)
			}
			if tc.repair != "" {
				if _, err := db.Exec(tc.repair); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := st.PutIncident(inc); err != nil {
					t.Fatal(err)
				}
			}
			if code, _ := planCall(t, a, http.MethodGet, tc.subject); code != http.StatusOK {
				t.Fatalf("recovered target: %d", code)
			}
			if code, _ := planCall(t, a, http.MethodPost, tc.subject); code != http.StatusAccepted {
				t.Fatalf("recovered request: %d", code)
			}
			if w := postJSON(a.handleLabels, "/labels", body); w.Code != http.StatusOK {
				t.Fatalf("recovered label: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestMissingPlanTargetsRemainNotFound(t *testing.T) {
	a := newTestAPI("", testStore(t), nil, func() Status { return Status{Running: true} })
	for _, subject := range []string{"flag:missing", "incident:missing"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			if code, _ := planCall(t, a, method, subject); code != http.StatusNotFound {
				t.Errorf("%s %s: %d", method, subject, code)
			}
		}
		if w := postJSON(a.handleLabels, "/labels", map[string]string{"subject": subject, "label": "ok"}); w.Code != http.StatusNotFound {
			t.Errorf("label %s: %d", subject, w.Code)
		}
	}
}

func TestPlanTargetIncidentAllowsMissingLinkedFlag(t *testing.T) {
	st := testStore(t)
	if err := st.PutIncident(model.IncidentReport{ID: "i1", FlagID: "missing", Rule: "rule", Timestamp: time.Now()}); err != nil {
		t.Fatal(err)
	}
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	rec := &planRecorder{ready: true, pending: map[string]bool{}}
	a.plan = rec.funcs()
	if code, _ := planCall(t, a, http.MethodGet, "incident:i1"); code != http.StatusOK {
		t.Fatalf("incident without linked flag: %d", code)
	}
	if code, _ := planCall(t, a, http.MethodPost, "incident:i1"); code != http.StatusAccepted {
		t.Fatalf("incident plan request: %d", code)
	}
	if w := postJSON(a.handleLabels, "/labels", map[string]string{"subject": "incident:i1", "label": "ok"}); w.Code != http.StatusOK {
		t.Fatalf("incident label: %d %s", w.Code, w.Body.String())
	}
}
