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

func TestStoredPlanReadFailureAndRecovery(t *testing.T) {
	for _, damage := range []string{"plan_json='null'", "plan_json='invalid'", "created_at='invalid'", "created_at='2000-01-01T00:00:00Z'", "unavailable table"} {
		t.Run(damage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "plans.db")
			st, err := store.Open(path, "")
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			if _, err := st.PutFlag(model.Flag{ID: "plan-source", Rule: "keychain-access", PID: 42, Severity: 3, TS: time.Now()}); err != nil {
				t.Fatal(err)
			}
			a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
			rec := &planRecorder{ready: true, pending: map[string]bool{}}
			a.plan = rec.funcs()
			const subject = "flag:plan-source"
			if code, response := planCall(t, a, http.MethodGet, subject); code != http.StatusOK || response.Status != "none" || response.Plan != nil {
				t.Fatalf("healthy missing plan: %d %+v", code, response)
			}
			target, found, err := a.resolvePlanTarget(subject)
			if err != nil || !found {
				t.Fatalf("target fixture: %v %v", found, err)
			}
			p := model.AdvisorPlan{Summary: "stored", EvidenceKey: planEvidenceKey(target), CreatedAt: time.Now().UTC()}
			if err := st.PutAdvisorPlan(subject, p); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			statement := "UPDATE advisor_plans SET " + damage
			if damage == "unavailable table" {
				statement = "ALTER TABLE advisor_plans RENAME TO unavailable_plans"
			}
			if _, err := db.Exec(statement); err != nil {
				t.Fatal(err)
			}
			if code, _ := planCall(t, a, http.MethodGet, subject); code != http.StatusServiceUnavailable {
				t.Errorf("failed stored-plan read reported availability: %d", code)
			}
			if len(rec.reqs) != 0 {
				t.Error("failed GET enqueued regeneration")
			}
			if code, _ := planCall(t, a, http.MethodPost, subject); code != http.StatusAccepted || len(rec.reqs) != 1 {
				t.Errorf("corrupt old plan prevented explicit regeneration: %d requests=%d", code, len(rec.reqs))
			}
			if damage == "unavailable table" {
				if _, err := db.Exec("ALTER TABLE unavailable_plans RENAME TO advisor_plans"); err != nil {
					t.Fatal(err)
				}
			}
			if err := st.PutAdvisorPlan(subject, p); err != nil {
				t.Fatal(err)
			}
			if code, response := planCall(t, a, http.MethodGet, subject); code != http.StatusOK || response.Plan == nil || response.Plan.Summary != p.Summary {
				t.Errorf("stored-plan recovery: %d %+v", code, response)
			}
		})
	}
}
