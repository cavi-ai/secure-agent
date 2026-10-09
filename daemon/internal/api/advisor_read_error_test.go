package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestAdvisorReadFailureKeepsCriticalFindingAndRejectsExplain(t *testing.T) {
	for _, severity := range []int{3, 2} {
		t.Run(fmt.Sprint(severity), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "advisor.db")
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
			now := time.Now().UTC()
			if _, err := st.PutFlag(model.Flag{ID: "advisor-source", Rule: "keychain-access", Severity: severity, PID: 42, TS: now}); err != nil {
				t.Fatal(err)
			}
			if severity == 2 {
				if _, err := st.PutFlag(model.Flag{ID: "critical-sibling", Rule: "keychain-access", Severity: 3, PID: 43, TS: now}); err != nil {
					t.Fatal(err)
				}
			}
			v := model.AdvisorVerdict{Rationale: "stored", CreatedAt: now}
			if err := st.PutAdvisorVerdict("advisor-source", "flag", v); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec("UPDATE advisor_verdicts SET created_at='invalid'"); err != nil {
				t.Fatal(err)
			}
			a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
			mux := a.buildMux()
			request := func(path string) *httptest.ResponseRecorder {
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
				return w
			}
			if w := request("/flags/advisor-source/explain"); w.Code != 503 {
				t.Errorf("corrupt verdict served as complete detail: %d %s", w.Code, w.Body.String())
			}
			w := request("/posture")
			var p Posture
			if w.Code != 200 {
				t.Fatalf("posture: %d %s", w.Code, w.Body.String())
			}
			if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
				t.Fatal(err)
			}
			if p.NeedsYou != 1 || p.CoverageCount != 1 || p.State != "critical" {
				t.Errorf("advisor failure hid critical finding or read fault: %+v", p)
			}
			w = request("/snapshot")
			var snapshot Snapshot
			if w.Code != 200 {
				t.Fatalf("snapshot: %d %s", w.Code, w.Body.String())
			}
			if err := json.Unmarshal(w.Body.Bytes(), &snapshot); err != nil {
				t.Fatal(err)
			}
			if snapshot.Posture.NeedsYou != 1 || snapshot.Posture.CoverageCount != 1 || snapshot.Posture.State != "critical" {
				t.Errorf("snapshot lost critical finding or read fault: %+v", snapshot.Posture)
			}
			if err := st.PutAdvisorVerdict("advisor-source", "flag", v); err != nil {
				t.Fatal(err)
			}
			if w := request("/flags/advisor-source/explain"); w.Code != 200 {
				t.Errorf("detail recovery: %d %s", w.Code, w.Body.String())
			}
			w = request("/posture")
			if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
				t.Fatal(err)
			}
			if p.NeedsYou != 1 || p.CoverageCount != 0 {
				t.Errorf("recovery lost critical finding or retained fault: %+v", p)
			}
		})
	}
}
