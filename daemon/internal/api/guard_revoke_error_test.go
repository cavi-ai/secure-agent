package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestGuardRevocationFailureAndRecovery(t *testing.T) {
	for _, kind := range []string{"rule", "path"} {
		for _, damage := range []string{"query", "delete", "closed"} {
			t.Run(kind+"/"+damage, func(t *testing.T) {
				dbPath := filepath.Join(t.TempDir(), "guard.db")
				st, err := store.Open(dbPath, "")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = st.Close() })
				db, err := sql.Open("sqlite", dbPath)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				table, route, operation, action := "guard_rules", "/guard/rules", "guard rule revocations", "guard-rule-revoke"
				query := url.Values{"agent": {"claude"}, "rule_id": {"fixture"}}
				if kind == "path" {
					table, route, operation, action = "guard_path_allows", "/guard/path-allow", "guard path revocations", "guard-path-allow-revoke"
					query.Set("path", "/synthetic/config")
				}
				for _, agent := range []string{"claude", "cursor"} {
					if kind == "rule" {
						st.PutGuardRule(store.GuardRule{Agent: agent, RuleID: "fixture", Decision: "allow", Source: "prompt"})
					} else if err := st.PutGuardPathAllow(store.GuardPathAllow{Agent: agent, RuleID: "fixture", Path: "/synthetic/config"}); err != nil {
						t.Fatal(err)
					}
				}
				a := newTestAPI(Deps{Store: st})
				switch damage {
				case "query":
					_, err = db.Exec("ALTER TABLE " + table + " RENAME TO unavailable_policy")
				case "delete":
					_, err = db.Exec("CREATE TRIGGER deny_guard_delete BEFORE DELETE ON " + table + " BEGIN SELECT RAISE(ABORT,'fixture mutation denied'); END")
				case "closed":
					err = st.Close()
				}
				if err != nil {
					t.Fatal(err)
				}
				w := call(t, a, http.MethodDelete, route+"?"+query.Encode(), "")
				if w.Code != http.StatusServiceUnavailable {
					t.Fatalf("failed revocation reported success: %d %s", w.Code, w.Body)
				}
				if strings.Contains(w.Body.String(), "fixture mutation denied") || strings.Contains(w.Body.String(), "sql:") || strings.Contains(w.Body.String(), table) {
					t.Fatalf("storage diagnostic exposed: %s", w.Body)
				}
				h := st.WriteHealth()
				if h.Failures != 1 || !slices.Equal(h.Active, []string{operation}) {
					t.Fatalf("revocation failure missing from write health: %+v", h)
				}
				if damage == "query" {
					if _, err := db.Exec("ALTER TABLE unavailable_policy RENAME TO " + table); err != nil {
						t.Fatal(err)
					}
				} else if damage == "delete" {
					if _, err := db.Exec("DROP TRIGGER deny_guard_delete"); err != nil {
						t.Fatal(err)
					}
				}
				var count, audits int
				if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 2 {
					t.Fatalf("failed revocation changed policy: %d %v", count, err)
				}
				if err := db.QueryRow("SELECT COUNT(*) FROM audit").Scan(&audits); err != nil || audits != 0 {
					t.Fatalf("failed revocation wrote success audit: %d %v", audits, err)
				}
				if damage == "closed" {
					return
				}
				readRemoval := func(q url.Values, want bool) {
					t.Helper()
					w := call(t, a, http.MethodDelete, route+"?"+q.Encode(), "")
					var response struct {
						Status  string `json:"status"`
						Removed bool   `json:"removed"`
					}
					if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != http.StatusOK || response.Status != "ok" || response.Removed != want {
						t.Fatalf("revocation response: %d %s %v", w.Code, w.Body, err)
					}
				}
				query.Set("rule_id", "missing")
				readRemoval(query, false)
				if h := st.WriteHealth(); h.Failures != 1 || !slices.Equal(h.Active, []string{operation}) {
					t.Fatalf("absent policy cleared failed revocation: %+v", h)
				}
				query.Set("rule_id", "fixture")
				readRemoval(query, true)
				readRemoval(query, false)
				if h := st.WriteHealth(); h.Failures != 1 || len(h.Active) != 0 {
					t.Fatalf("successful retry did not recover health: %+v", h)
				}
				if err := db.QueryRow("SELECT COUNT(*) FROM " + table + " WHERE agent='cursor'").Scan(&count); err != nil || count != 1 {
					t.Fatalf("revocation changed another agent: %d %v", count, err)
				}
				if audits := st.RecentAudit(10); len(audits) != 1 || audits[0].Action != action || audits[0].Rule != "claude/fixture" {
					t.Fatalf("revocation audit: %+v", audits)
				}
			})
		}
	}
}
