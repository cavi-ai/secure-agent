package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestExpectedEgressWriteFailureAndRecovery(t *testing.T) {
	for _, damage := range []string{"create-query", "create-insert", "create-decode", "revoke-query", "revoke-update"} {
		t.Run(damage, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "expected.db")
			st, err := store.Open(dbPath, "")
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			db, err := sql.Open("sqlite", dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			scope := store.EgressScope{Agent: "claude", ExePath: "/usr/bin/claude", Harness: "claude", Workspace: "/work/a"}
			if err := st.RecordEgressObservationForTest(store.EgressObservation{Scope: scope, Host: "203.0.113.1", Protocol: "tcp", Port: 443, At: time.Now().UTC()}); err != nil {
				t.Fatal(err)
			}
			episodes := st.ListEgressEpisodes(10)
			if len(episodes) != 1 {
				t.Fatal("missing episode fixture")
			}
			rule, err := st.CreateExpectedEgressRule(store.ExpectedEgressRule{Agent: "claude", Kind: "destination", Host: "203.0.113.1", Protocol: "tcp", Port: 443})
			if err != nil {
				t.Fatal(err)
			}
			baseline := st.ListExpectedEgressRules()
			mux := newTestAPI("", st, nil, nil).buildMux()
			request := func(method, path, body string) *httptest.ResponseRecorder {
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
				return w
			}
			kind := "scope"
			if damage == "create-decode" {
				kind = "destination"
			}
			createBody := `{"episode_id":"` + episodes[0].ID + `","kind":"` + kind + `"}`
			revoking := strings.HasPrefix(damage, "revoke")
			mutate := func() *httptest.ResponseRecorder {
				if revoking {
					return request(http.MethodDelete, "/expected-egress?id="+rule.ID, "")
				}
				return request(http.MethodPost, "/expected-egress", createBody)
			}
			switch damage {
			case "create-query", "revoke-query":
				_, err = db.Exec(`ALTER TABLE expected_egress_rules RENAME TO unavailable_expected`)
			case "create-insert":
				_, err = db.Exec(`CREATE TRIGGER deny_expected_insert BEFORE INSERT ON expected_egress_rules BEGIN SELECT RAISE(ABORT,'test mutation denied'); END`)
			case "create-decode":
				_, err = db.Exec(`UPDATE expected_egress_rules SET created_at='invalid' WHERE id=?`, rule.ID)
			case "revoke-update":
				_, err = db.Exec(`CREATE TRIGGER deny_expected_update BEFORE UPDATE ON expected_egress_rules BEGIN SELECT RAISE(ABORT,'test mutation denied'); END`)
			}
			if err != nil {
				t.Fatal(err)
			}
			if w := mutate(); w.Code != http.StatusServiceUnavailable {
				t.Errorf("storage failure misreported as invalid/missing rule: %d %s", w.Code, w.Body.String())
			}
			if len(st.RecentAudit(10)) != 0 {
				t.Error("failed mutation wrote a success audit")
			}
			label := "expected egress create"
			if revoking {
				label = "expected egress revoke"
			}
			h := st.WriteHealth()
			if h.Failures != 1 || !slices.Contains(h.Active, label) {
				t.Errorf("failed mutation missing from write health: %+v", h)
			}
			if w := request(http.MethodPost, "/expected-egress", `{"episode_id":"`+episodes[0].ID+`","kind":"invalid"}`); w.Code != http.StatusBadRequest {
				t.Errorf("invalid input lost 400: %d", w.Code)
			}
			if _, err := st.CreateExpectedEgressRule(store.ExpectedEgressRule{}); !errors.Is(err, store.ErrInvalidExpectedEgressRule) {
				t.Errorf("invalid rule lost its validation error: %v", err)
			}
			switch damage {
			case "create-query", "revoke-query":
				_, err = db.Exec(`ALTER TABLE unavailable_expected RENAME TO expected_egress_rules`)
			case "create-insert":
				_, err = db.Exec(`DROP TRIGGER deny_expected_insert`)
			case "create-decode":
				_, err = db.Exec(`UPDATE expected_egress_rules SET created_at=? WHERE id=?`, rule.CreatedAt.Format(time.RFC3339Nano), rule.ID)
			case "revoke-update":
				_, err = db.Exec(`DROP TRIGGER deny_expected_update`)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := st.ListExpectedEgressRules(); !reflect.DeepEqual(got, baseline) {
				t.Errorf("failed mutation changed rule state: got %+v, want %+v", got, baseline)
			}
			if w := request(http.MethodDelete, "/expected-egress?id=00000000000000000000000000000000", ""); w.Code != http.StatusNotFound {
				t.Errorf("healthy missing rule lost 404: %d", w.Code)
			}
			if got := st.WriteHealth(); got.Failures != h.Failures || !slices.Contains(got.Active, label) {
				t.Errorf("validation, absence or healthy reads erased the write fault: %+v", got)
			}
			w := mutate()
			if w.Code != http.StatusOK {
				t.Fatalf("mutation did not recover: %d %s", w.Code, w.Body.String())
			}
			if revoking {
				var stored string
				if err := db.QueryRow(`SELECT revoked_at FROM expected_egress_rules WHERE id=?`, rule.ID).Scan(&stored); err != nil || stored == "" {
					t.Errorf("recovered revoke did not persist: %q %v", stored, err)
				}
			} else {
				var saved store.ExpectedEgressRule
				if json.Unmarshal(w.Body.Bytes(), &saved) != nil || saved.Kind != kind || saved.Agent != scope.Agent || kind == "scope" && (saved.ExePath != scope.ExePath || saved.Harness != scope.Harness || saved.Workspace != scope.Workspace) || kind == "destination" && saved.ID != rule.ID {
					t.Errorf("recovered create returned wrong rule: %s", w.Body.String())
				}
			}
			action := "expected-egress-create"
			if revoking {
				action = "expected-egress-revoke"
			}
			if audit := st.RecentAudit(10); len(audit) != 1 || audit[0].Action != action {
				t.Errorf("wrong success audit: %+v", audit)
			}
			if got := st.WriteHealth(); got.Failures != h.Failures || len(got.Active) != 0 {
				t.Errorf("recovery lost cumulative write history: %+v", got)
			}
		})
	}
}
