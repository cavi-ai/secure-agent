package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestExpectedEgressIdentityFailureAndRecovery(t *testing.T) {
	for _, damage := range []string{"host", "scope", "port", "kind", "noncanonical", "unused-scope", "id"} {
		t.Run(damage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "expected.db")
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
			scope := store.EgressScope{Agent: "claude", ExePath: "/usr/bin/claude", Harness: "claude", Workspace: "/work/a"}
			at := time.Now().UTC()
			for i := 0; i < 5; i++ {
				if err := st.RecordEgressObservationForTest(store.EgressObservation{Scope: scope, Host: "api.example.com", Protocol: "tcp", Port: 443, At: at.Add(time.Duration(i-4) * time.Hour)}); err != nil {
					t.Fatal(err)
				}
			}
			kind := "destination"
			if damage == "scope" {
				kind = "scope"
			}
			rule, err := st.CreateExpectedEgressRule(store.ExpectedEgressRule{Agent: scope.Agent, Kind: kind, Host: "api.example.com", Protocol: "tcp", Port: 443, ExePath: scope.ExePath, Harness: scope.Harness, Workspace: scope.Workspace})
			if err != nil {
				t.Fatal(err)
			}
			mux := newTestAPI("", st, nil, nil).buildMux()
			request := func(method, path, body string) *httptest.ResponseRecorder {
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
				return w
			}
			getEpisodes := func() []egressEpisodeView {
				t.Helper()
				w := request(http.MethodGet, "/egress/episodes", "")
				var response struct {
					Episodes []egressEpisodeView `json:"episodes"`
				}
				if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil || len(response.Episodes) != 1 || response.Episodes[0].ExpectedRuleID != rule.ID || response.Episodes[0].Candidate {
					t.Fatalf("healthy classification: %d %s", w.Code, w.Body.String())
				}
				return response.Episodes
			}
			baseline := getEpisodes()
			body := `{"episode_id":"` + baseline[0].ID + `","kind":"` + kind + `"}`
			storedID := rule.ID
			switch damage {
			case "host":
				_, err = db.Exec(`UPDATE expected_egress_rules SET host='other.example.com' WHERE id=?`, rule.ID)
			case "scope":
				_, err = db.Exec(`UPDATE expected_egress_rules SET workspace='/work/b' WHERE id=?`, rule.ID)
			case "port":
				_, err = db.Exec(`UPDATE expected_egress_rules SET port=70000 WHERE id=?`, rule.ID)
			case "kind":
				_, err = db.Exec(`UPDATE expected_egress_rules SET kind='invalid' WHERE id=?`, rule.ID)
			case "noncanonical":
				_, err = db.Exec(`UPDATE expected_egress_rules SET host='API.EXAMPLE.COM' WHERE id=?`, rule.ID)
			case "unused-scope":
				_, err = db.Exec(`UPDATE expected_egress_rules SET workspace='/phantom' WHERE id=?`, rule.ID)
			case "id":
				storedID = "00000000000000000000000000000000"
				_, err = db.Exec(`UPDATE expected_egress_rules SET id=? WHERE id=?`, storedID, rule.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{"/expected-egress", "/egress/episodes"} {
				if w := request(http.MethodGet, path, ""); w.Code != http.StatusServiceUnavailable {
					t.Errorf("inconsistent rule accepted by %s: %d %s", path, w.Code, w.Body.String())
				}
			}
			if damage != "id" {
				if w := request(http.MethodPost, "/expected-egress", body); w.Code != http.StatusServiceUnavailable {
					t.Errorf("reapproval returned mismatched stored rule: %d %s", w.Code, w.Body.String())
				}
			}
			if rows, err := st.ListExpectedEgressRulesResult(); err == nil || rows != nil {
				t.Errorf("invalid rules escaped checked list: %+v %v", rows, err)
			}
			if match, err := st.ExpectedEgressMatcherResult(); err == nil || match != nil {
				t.Error("invalid rules escaped checked matcher")
			}
			if audit := st.RecentAudit(10); len(audit) != 0 {
				t.Errorf("inconsistent reapproval produced a success audit: %+v", audit)
			}
			h := st.WriteHealth()
			_, err = db.Exec(`UPDATE expected_egress_rules SET id=?,agent=?,kind=?,host=?,protocol=?,port=?,exe_path=?,harness=?,workspace=? WHERE id=?`, rule.ID, rule.Agent, rule.Kind, rule.Host, rule.Protocol, rule.Port, rule.ExePath, rule.Harness, rule.Workspace, storedID)
			if err != nil {
				t.Fatal(err)
			}
			if rules, err := st.ListExpectedEgressRulesResult(); err != nil || !reflect.DeepEqual(rules, []store.ExpectedEgressRule{rule}) {
				t.Errorf("repair changed persisted fields: %+v %v", rules, err)
			}
			if got := getEpisodes(); !reflect.DeepEqual(got, baseline) {
				t.Error("repair changed episode fields or classification")
			}
			w := request(http.MethodPost, "/expected-egress", body)
			var saved store.ExpectedEgressRule
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &saved) != nil || !reflect.DeepEqual(saved, rule) {
				t.Errorf("reapproval did not recover from observed evidence: %d %s", w.Code, w.Body.String())
			}
			if got := st.WriteHealth(); got.ReadFailures != h.ReadFailures || got.Failures != h.Failures || len(got.ReadActive) != 0 || len(got.Active) != 0 {
				t.Errorf("repair lost failure history: %+v", got)
			}
		})
	}
}
