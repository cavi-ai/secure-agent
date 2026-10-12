package api

import (
	"database/sql"
	"encoding/json"
	"github.com/cavi-ai/secure-agent/daemon/internal/testutil"
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

// A successful operator response requires both the rule and its audit record.
// An audit failure must leave the decision retryable, including revocation.
func TestExpectedEgressAuditRollbackAndRecovery(t *testing.T) {
	for _, decision := range []string{"create", "active", "reactivate", "revoke"} {
		for _, failure := range []string{"insert", "prune"} {
			t.Run(decision+"/"+failure, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "expected.db")
				st, err := store.Open(path, "")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { st.Close() })
				db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(3000)")
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				obs := store.EgressObservation{Scope: store.EgressScope{Agent: "claude", ExePath: "/usr/bin/claude", Harness: "claude", Workspace: "/work/a"}, Host: "203.0.113.1", Protocol: "tcp", Port: 443, At: time.Now().UTC()}
				if err := st.RecordEgressObservationForTest(obs); err != nil {
					t.Fatal(err)
				}
				eps := testutil.Read[[]store.EgressEpisode](t)(st.ListEgressEpisodes(10))
				if len(eps) != 1 {
					t.Fatal("missing episode")
				}
				var rule store.ExpectedEgressRule
				if decision != "create" {
					rule, err = st.CreateExpectedEgressRule(store.ExpectedEgressRule{Agent: "claude", Kind: "destination", Host: obs.Host, Protocol: "tcp", Port: 443})
					if err != nil {
						t.Fatal(err)
					}
					if decision == "reactivate" {
						if err := st.RevokeExpectedEgressRule(rule.ID); err != nil {
							t.Fatal(err)
						}
					}
				}
				st.PutAudit(store.AuditEntry{Action: "fixture-existing", Detail: "existing audit"})
				baselineRules := testutil.Read[[]store.ExpectedEgressRule](t)(st.ListExpectedEgressRules())
				baselineAudit := st.RecentAudit(10)
				if len(baselineAudit) != 1 {
					t.Fatal("missing audit fixture")
				}
				mux := newTestAPI(Deps{SocketPath: "", Store: st, Killer: nil, Status: nil}).buildMux()
				request := func(method, url, body string) *httptest.ResponseRecorder {
					w := httptest.NewRecorder()
					mux.ServeHTTP(w, httptest.NewRequest(method, url, strings.NewReader(body)))
					return w
				}
				mutate := func() *httptest.ResponseRecorder {
					if decision == "revoke" {
						return request(http.MethodDelete, "/expected-egress?id="+rule.ID, "")
					}
					return request(http.MethodPost, "/expected-egress", `{"episode_id":"`+eps[0].ID+`","kind":"destination"}`)
				}
				if failure == "insert" {
					_, err = db.Exec(`CREATE TRIGGER deny_expected_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`)
				} else {
					// Inserts still succeed; audit retention fails after the insert.
					_, err = db.Exec(`ALTER TABLE audit RENAME COLUMN id TO unavailable_id`)
				}
				if err != nil {
					t.Fatal(err)
				}
				w := mutate()
				if w.Code != http.StatusServiceUnavailable {
					t.Errorf("audit failure returned success: %d %s", w.Code, w.Body.String())
				}
				if got := testutil.Read[[]store.ExpectedEgressRule](t)(st.ListExpectedEgressRules()); !reflect.DeepEqual(got, baselineRules) {
					t.Errorf("audit failure changed rules: got %+v, want %+v", got, baselineRules)
				}
				var count int
				if err := db.QueryRow(`SELECT count(*) FROM audit`).Scan(&count); err != nil || count != 1 {
					t.Errorf("failed decision left an audit record: count=%d err=%v", count, err)
				}
				label := "expected egress create"
				if decision == "revoke" {
					label = "expected egress revoke"
				}
				h := st.WriteHealth()
				if !slices.Contains(h.Active, label) || !slices.Contains(h.Active, "operator audit") {
					t.Errorf("audit failure missing from mutation health: %+v", h)
				}
				if w := request(http.MethodPost, "/expected-egress", `{"episode_id":"`+eps[0].ID+`","kind":"invalid"}`); w.Code != http.StatusBadRequest {
					t.Errorf("invalid request: %d", w.Code)
				}
				if w := request(http.MethodDelete, "/expected-egress?id=00000000000000000000000000000000", ""); w.Code != http.StatusNotFound {
					t.Errorf("missing rule: %d", w.Code)
				}
				if got := st.WriteHealth(); !reflect.DeepEqual(got, h) {
					t.Errorf("invalid or absent decision erased audit fault: %+v", got)
				}
				if failure == "insert" {
					_, err = db.Exec(`DROP TRIGGER deny_expected_audit`)
				} else {
					_, err = db.Exec(`ALTER TABLE audit RENAME COLUMN unavailable_id TO id`)
				}
				if err != nil {
					t.Fatal(err)
				}
				if got := st.RecentAudit(10); !reflect.DeepEqual(got, baselineAudit) {
					t.Errorf("failed decision changed audit history: %+v", got)
				}
				w = mutate()
				if w.Code != http.StatusOK {
					t.Fatalf("retry failed: %d %s", w.Code, w.Body.String())
				}
				action, toMode := "expected-egress-create", "destination"
				if decision == "revoke" {
					action, toMode = "expected-egress-revoke", "revoked"
					if got := testutil.Read[[]store.ExpectedEgressRule](t)(st.ListExpectedEgressRules()); len(got) != 1 || got[0].RevokedAt == nil {
						t.Errorf("retry did not revoke: %+v", got)
					}
				} else {
					var saved store.ExpectedEgressRule
					if err := json.Unmarshal(w.Body.Bytes(), &saved); err != nil || saved.Agent != "claude" || saved.Kind != "destination" || saved.Host != obs.Host || saved.Protocol != "tcp" || saved.Port != 443 || saved.RevokedAt != nil {
						t.Fatalf("wrong saved rule: %+v %v", saved, err)
					}
					if decision == "active" && !reflect.DeepEqual(saved, rule) {
						t.Error("idempotent approval changed the active rule")
					}
					rule = saved
				}
				audits := st.RecentAudit(10)
				if len(audits) != 2 || audits[0].Action != action || audits[0].Rule != rule.ID || audits[0].ToMode != toMode || !reflect.DeepEqual(audits[1], baselineAudit[0]) {
					t.Errorf("retry audit mismatch: %+v", audits)
				}
				if got := st.WriteHealth(); got.Failures != h.Failures || len(got.Active) != 0 {
					t.Errorf("recovery lost history or kept faults: %+v", got)
				}
				persisted := testutil.Read[[]store.ExpectedEgressRule](t)(st.ListExpectedEgressRules())
				st.Close()
				reopened, err := store.Open(path, "")
				if err != nil {
					t.Fatal(err)
				}
				st = reopened
				if !reflect.DeepEqual(testutil.Read[[]store.ExpectedEgressRule](t)(st.ListExpectedEgressRules()), persisted) || !reflect.DeepEqual(st.RecentAudit(10), audits) {
					t.Error("rule or audit lost on reopen")
				}
			})
		}
	}
}
