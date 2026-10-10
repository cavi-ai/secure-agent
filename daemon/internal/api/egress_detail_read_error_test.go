package api

import (
	"database/sql"
	"encoding/json"
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

func TestEgressDetailReadFailurePreventsActionsAndRecovers(t *testing.T) {
	for _, damage := range []string{"intervals", "sessions", "count", "unavailable"} {
		t.Run(damage, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "egress.db")
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
			at := time.Now().UTC()
			scope := store.EgressScope{Agent: "claude", ExePath: "/usr/bin/claude", Harness: "claude", Workspace: "/work/a"}
			for i := 0; i < 5; i++ {
				if err := st.RecordEgressObservationForTest(store.EgressObservation{Scope: scope, SessionID: "s1", Host: "203.0.113.1", Protocol: "tcp", Port: 443, At: at.Add(time.Duration(i-4) * time.Hour)}); err != nil {
					t.Fatal(err)
				}
			}
			rows := st.ListEgressEpisodes(10)
			if len(rows) != 1 || !rows[0].Recurring || !rows[0].ScopeComplete {
				t.Fatalf("invalid fixture: %+v", rows)
			}
			baseline := rows[0]
			var intervals, sessions string
			var count int
			if err := db.QueryRow(`SELECT intervals_json,session_ids_json,count FROM egress_episodes WHERE id=?`, baseline.ID).Scan(&intervals, &sessions, &count); err != nil {
				t.Fatal(err)
			}
			a := newTestAPI("", st, nil, nil)
			queued := 0
			a.egressAdvisor = func(e store.EgressEpisode) bool {
				queued++
				if !reflect.DeepEqual(e, baseline) {
					t.Errorf("advisor received changed evidence: got %+v, want %+v", e, baseline)
				}
				return true
			}
			mux := a.buildMux()
			assess := func() *httptest.ResponseRecorder {
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/egress/episodes/"+baseline.ID+"/assess", nil))
				return w
			}
			approve := func() *httptest.ResponseRecorder {
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/expected-egress", strings.NewReader(`{"episode_id":"`+baseline.ID+`","kind":"scope"}`)))
				return w
			}
			switch damage {
			case "intervals":
				_, err = db.Exec(`UPDATE egress_episodes SET intervals_json='invalid' WHERE id=?`, baseline.ID)
			case "sessions":
				_, err = db.Exec(`UPDATE egress_episodes SET session_ids_json='invalid' WHERE id=?`, baseline.ID)
			case "count":
				_, err = db.Exec(`UPDATE egress_episodes SET count='invalid' WHERE id=?`, baseline.ID)
			case "unavailable":
				_, err = db.Exec(`ALTER TABLE egress_episodes RENAME TO unavailable_egress`)
			}
			if err != nil {
				t.Fatal(err)
			}
			if w := assess(); w.Code != http.StatusServiceUnavailable {
				t.Errorf("failed assessment evidence treated as absent: %d %s", w.Code, w.Body.String())
			}
			if w := approve(); w.Code != http.StatusServiceUnavailable {
				t.Errorf("failed approval evidence treated as absent: %d %s", w.Code, w.Body.String())
			}
			if queued != 0 || len(st.ListExpectedEgressRules()) != 0 || len(st.RecentAudit(10)) != 0 {
				t.Error("failed evidence queued advice or wrote rules/audit")
			}
			if episode, found, err := st.GetEgressEpisodeResult(baseline.ID); err == nil || found || !reflect.DeepEqual(episode, store.EgressEpisode{}) {
				t.Errorf("failed detail read returned partial evidence: episode=%+v found=%v err=%v", episode, found, err)
			}
			h := st.WriteHealth()
			if h.ReadFailures != 3 || !slices.Contains(h.ReadActive, "egress episode detail") {
				t.Errorf("detail failures were hidden: %+v", h)
			}
			if damage == "unavailable" {
				_, err = db.Exec(`ALTER TABLE unavailable_egress RENAME TO egress_episodes`)
			} else {
				_, err = db.Exec(`UPDATE egress_episodes SET intervals_json=?,session_ids_json=?,count=? WHERE id=?`, intervals, sessions, count, baseline.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			if w := assess(); w.Code != http.StatusOK || queued != 1 {
				t.Fatalf("assessment did not recover: %d %s queued=%d", w.Code, w.Body.String(), queued)
			}
			w := approve()
			var rule store.ExpectedEgressRule
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &rule) != nil || rule.Kind != "scope" || rule.Agent != scope.Agent || rule.ExePath != scope.ExePath || rule.Workspace != scope.Workspace || rule.Harness != scope.Harness {
				t.Fatalf("approval did not recover from observed scope: %d %s", w.Code, w.Body.String())
			}
			if rules, audit := st.ListExpectedEgressRules(), st.RecentAudit(10); len(rules) != 1 || len(audit) != 1 || audit[0].Action != "expected-egress-create" || audit[0].Rule != rule.ID {
				t.Fatalf("recovered approval missing rule or audit: rules=%+v audit=%+v", rules, audit)
			}
			if got := st.WriteHealth(); got.ReadFailures != h.ReadFailures || len(got.ReadActive) != 0 {
				t.Errorf("repair lost failure history: %+v", got)
			}
		})
	}
}

func TestEgressDetailMissingAndClosedStore(t *testing.T) {
	st := testStore(t)
	a := newTestAPI("", st, nil, nil)
	queued := 0
	a.egressAdvisor = func(store.EgressEpisode) bool { queued++; return true }
	mux := a.buildMux()
	const id = "00000000000000000000000000000000"
	for _, closed := range []bool{false, true} {
		want := http.StatusNotFound
		if closed {
			st.Close()
			want = http.StatusServiceUnavailable
		}
		for _, path := range []string{"/egress/episodes/" + id + "/assess", "/expected-egress"} {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"episode_id":"`+id+`","kind":"scope"}`)))
			if w.Code != want || queued != 0 {
				t.Errorf("closed=%v path=%s: got %d, want %d; queued=%d", closed, path, w.Code, want, queued)
			}
		}
		if !closed && (st.WriteHealth().ReadFailures != 0 || len(st.WriteHealth().ReadActive) != 0) {
			t.Error("healthy absence marked storage unhealthy")
		}
	}
}
