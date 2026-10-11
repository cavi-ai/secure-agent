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

func TestEgressEpisodesReadFailureAndRecovery(t *testing.T) {
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
			for i, host := range []string{"203.0.113.1", "203.0.113.2"} {
				if err := st.RecordEgressObservationForTest(store.EgressObservation{Scope: store.EgressScope{Agent: "claude"}, Host: host, Protocol: "tcp", Port: 443, At: at.Add(time.Duration(i) * time.Second)}); err != nil {
					t.Fatal(err)
				}
			}
			a := newTestAPI("", st, nil, nil)
			mux := a.buildMux()
			request := func() *httptest.ResponseRecorder {
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, httptest.NewRequest("GET", "/egress/episodes", nil))
				return w
			}
			decode := func(w *httptest.ResponseRecorder) []egressEpisodeView {
				t.Helper()
				var response struct {
					Episodes []egressEpisodeView `json:"episodes"`
				}
				if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil || len(response.Episodes) != 2 {
					t.Fatalf("healthy read: %d %s", w.Code, w.Body.String())
				}
				return response.Episodes
			}
			baseline := decode(request())
			// Damage the older row after a valid row has been scanned.
			id := baseline[1].ID
			var intervals, sessions string
			var count int
			if err := db.QueryRow(`SELECT intervals_json,session_ids_json,count FROM egress_episodes WHERE id=?`, id).Scan(&intervals, &sessions, &count); err != nil {
				t.Fatal(err)
			}
			switch damage {
			case "intervals":
				_, err = db.Exec(`UPDATE egress_episodes SET intervals_json='invalid' WHERE id=?`, id)
			case "sessions":
				_, err = db.Exec(`UPDATE egress_episodes SET session_ids_json='invalid' WHERE id=?`, id)
			case "count":
				_, err = db.Exec(`UPDATE egress_episodes SET count='invalid' WHERE id=?`, id)
			case "unavailable":
				_, err = db.Exec(`ALTER TABLE egress_episodes RENAME TO unavailable_egress`)
			}
			if err != nil {
				t.Fatal(err)
			}
			if w := request(); w.Code != http.StatusServiceUnavailable {
				t.Errorf("failed core read returned success: %d %s", w.Code, w.Body.String())
			}
			h := st.WriteHealth()
			if h.ReadFailures != 1 || !slices.Contains(h.ReadActive, "egress episodes") {
				t.Errorf("core egress read failure hidden: %+v", h)
			}
			if rows, err := st.ListEgressEpisodesForReviewResult(); err == nil || rows != nil {
				t.Errorf("checked store returned incomplete evidence: rows=%+v err=%v", rows, err)
			}
			h = st.WriteHealth()
			if h.ReadFailures != 2 || !slices.Contains(h.ReadActive, "egress episodes") {
				t.Errorf("checked read did not retain one fault per call: %+v", h)
			}
			if damage == "unavailable" {
				_, err = db.Exec(`ALTER TABLE unavailable_egress RENAME TO egress_episodes`)
			} else {
				_, err = db.Exec(`UPDATE egress_episodes SET intervals_json=?,session_ids_json=?,count=? WHERE id=?`, intervals, sessions, count, id)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := decode(request()); !reflect.DeepEqual(got, baseline) {
				t.Errorf("repair changed episode data or ordering: got %+v, want %+v", got, baseline)
			}
			if got := st.WriteHealth(); got.ReadFailures != h.ReadFailures || len(got.ReadActive) != 0 {
				t.Errorf("repair lost read failure history: %+v", got)
			}
		})
	}
}

func TestEgressEpisodesEmptyAndClosedStore(t *testing.T) {
	st := testStore(t)
	a := newTestAPI("", st, nil, nil)
	mux := a.buildMux()
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/egress/episodes", nil))
	var response struct {
		Episodes []egressEpisodeView `json:"episodes"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Episodes == nil || len(response.Episodes) != 0 {
		t.Fatalf("empty store did not return an empty array: %d %s", w.Code, w.Body.String())
	}
	st.Close()
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/egress/episodes", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed store returned success: %d %s", w.Code, w.Body.String())
	}
}
