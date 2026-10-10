package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestExpectedEgressReadFailureAndRecovery(t *testing.T) {
	for _, damage := range []string{"active-port", "revoked-port", "created-at", "revoked-at", "unavailable"} {
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
			at := time.Now().UTC()
			for i := 0; i < 5; i++ {
				if err := st.RecordEgressObservationForTest(store.EgressObservation{Scope: scope, Host: "203.0.113.1", Protocol: "tcp", Port: 443, At: at.Add(time.Duration(i-4) * time.Hour)}); err != nil {
					t.Fatal(err)
				}
			}
			exact, err := st.CreateExpectedEgressRule(store.ExpectedEgressRule{Agent: "claude", Kind: "destination", Host: "203.0.113.1", Protocol: "tcp", Port: 443})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := st.CreateExpectedEgressRule(store.ExpectedEgressRule{Agent: "claude", Kind: "scope", ExePath: scope.ExePath, Harness: scope.Harness, Workspace: scope.Workspace}); err != nil {
				t.Fatal(err)
			}
			revoked, err := st.CreateExpectedEgressRule(store.ExpectedEgressRule{Agent: "claude", Kind: "destination", Host: "203.0.113.2", Protocol: "tcp", Port: 443})
			if err != nil {
				t.Fatal(err)
			}
			if err := st.RevokeExpectedEgressRule(revoked.ID); err != nil {
				t.Fatal(err)
			}
			mux := newTestAPI("", st, nil, nil).buildMux()
			get := func(path string) *httptest.ResponseRecorder {
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
				return w
			}
			decodeRules := func(w *httptest.ResponseRecorder) []store.ExpectedEgressRule {
				t.Helper()
				var response struct {
					Rules []store.ExpectedEgressRule `json:"rules"`
				}
				if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil || len(response.Rules) != 3 {
					t.Fatalf("healthy rules: %d %s", w.Code, w.Body.String())
				}
				return response.Rules
			}
			decodeEpisodes := func(w *httptest.ResponseRecorder) []egressEpisodeView {
				t.Helper()
				var response struct {
					Episodes []egressEpisodeView `json:"episodes"`
				}
				if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil || len(response.Episodes) != 1 || response.Episodes[0].Candidate || response.Episodes[0].ExpectedRuleID != exact.ID {
					t.Fatalf("expected destination lost: %d %s", w.Code, w.Body.String())
				}
				return response.Episodes
			}
			baselineRules := decodeRules(get("/expected-egress"))
			baselineEpisodes := decodeEpisodes(get("/egress/episodes"))
			matcherFails := damage == "active-port" || damage == "unavailable"
			switch damage {
			case "active-port":
				_, err = db.Exec(`UPDATE expected_egress_rules SET port='invalid' WHERE id=?`, exact.ID)
			case "revoked-port":
				_, err = db.Exec(`UPDATE expected_egress_rules SET port='invalid' WHERE id=?`, revoked.ID)
			case "created-at":
				_, err = db.Exec(`UPDATE expected_egress_rules SET created_at='invalid' WHERE id=?`, exact.ID)
			case "revoked-at":
				_, err = db.Exec(`UPDATE expected_egress_rules SET revoked_at='invalid' WHERE id=?`, revoked.ID)
			case "unavailable":
				_, err = db.Exec(`ALTER TABLE expected_egress_rules RENAME TO unavailable_expected`)
			}
			if err != nil {
				t.Fatal(err)
			}
			if w := get("/expected-egress"); w.Code != http.StatusServiceUnavailable {
				t.Errorf("failed rule read returned success: %d %s", w.Code, w.Body.String())
			}
			if matcherFails {
				if w := get("/egress/episodes"); w.Code != http.StatusServiceUnavailable {
					t.Errorf("failed matcher silently reclassified episodes: %d %s", w.Code, w.Body.String())
				}
			} else {
				decodeEpisodes(get("/egress/episodes"))
			}
			h := st.WriteHealth()
			wantFailures := uint64(1)
			if matcherFails {
				wantFailures++
			}
			if h.ReadFailures != wantFailures || !slices.Contains(h.ReadActive, "expected egress rules") || matcherFails && !slices.Contains(h.ReadActive, "expected egress matcher") {
				t.Errorf("rule read faults hidden or erased by narrower matcher: %+v", h)
			}
			if rules, err := st.ListExpectedEgressRulesResult(); err == nil || rules != nil {
				t.Errorf("failed rule list returned partial evidence: rules=%+v err=%v", rules, err)
			}
			if matcherFails {
				if match, err := st.ExpectedEgressMatcherResult(); err == nil || match != nil {
					t.Error("failed matcher exposed partial classification")
				}
			}
			h = st.WriteHealth()
			if damage == "unavailable" {
				_, err = db.Exec(`ALTER TABLE unavailable_expected RENAME TO expected_egress_rules`)
			} else {
				_, err = db.Exec(`UPDATE expected_egress_rules SET port=?,created_at=? WHERE id=?`, exact.Port, exact.CreatedAt.Format(time.RFC3339Nano), exact.ID)
				if err == nil {
					_, err = db.Exec(`UPDATE expected_egress_rules SET port=?,revoked_at=? WHERE id=?`, revoked.Port, baselineRules[2].RevokedAt.Format(time.RFC3339Nano), revoked.ID)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := decodeRules(get("/expected-egress")); !reflect.DeepEqual(got, baselineRules) {
				t.Errorf("repair changed rule fields/order: got %+v, want %+v", got, baselineRules)
			}
			if got := decodeEpisodes(get("/egress/episodes")); !reflect.DeepEqual(got, baselineEpisodes) {
				t.Error("repair changed episode evidence/classification")
			}
			if got := st.WriteHealth(); got.ReadFailures != h.ReadFailures || len(got.ReadActive) != 0 {
				t.Errorf("repair erased failure history: %+v", got)
			}
			if len(st.RecentAudit(10)) != 0 {
				t.Error("read-only requests wrote audit entries")
			}
		})
	}
}

func TestExpectedEgressReadsEmptyAndClosedStore(t *testing.T) {
	st := testStore(t)
	mux := newTestAPI("", st, nil, nil).buildMux()
	for _, closed := range []bool{false, true} {
		if closed {
			st.Close()
		}
		for _, path := range []string{"/expected-egress", "/egress/episodes"} {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
			if closed {
				if w.Code != http.StatusServiceUnavailable {
					t.Errorf("closed store returned success for %s: %d %s", path, w.Code, w.Body.String())
				}
			} else {
				var response struct {
					Rules    []json.RawMessage `json:"rules"`
					Episodes []json.RawMessage `json:"episodes"`
				}
				if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil || path == "/expected-egress" && response.Rules == nil || path == "/egress/episodes" && response.Episodes == nil {
					t.Errorf("empty store lost empty array for %s: %d %s", path, w.Code, w.Body.String())
				}
			}
		}
	}
}
