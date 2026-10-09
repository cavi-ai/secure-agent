package api

import (
	"database/sql"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestEventReadFailureDoesNotReturnSuccessfulPartialData(t *testing.T) {
	for _, damage := range []string{"pid='invalid'", "ts='invalid'", "cost_usd=1e999"} {
		t.Run(damage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "events.db")
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
			for _, sid := range []string{"bad", "good"} {
				if _, err := st.PutEvent(event.Event{Kind: event.KindToolCall, TS: time.Now(), PID: 1, SessionID: sid}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := db.Exec("UPDATE events SET " + damage + " WHERE session_id='bad'"); err != nil {
				t.Fatal(err)
			}
			a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
			for _, url := range []string{"/events", "/sessions/bad/timeline", "/snapshot"} {
				w := httptest.NewRecorder()
				a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", url, nil))
				if w.Code != 503 {
					t.Fatalf("%s returned successful partial data: %d %s", url, w.Code, w.Body.String())
				}
			}
			h := st.WriteHealth()
			if h.ReadFailures != 3 || !slices.Equal(h.ReadActive, []string{"events"}) || h.Failures != 0 {
				t.Fatalf("event read failure hidden or confused with lost writes: %+v", h)
			}
			if _, err := db.Exec("UPDATE events SET pid=1, cost_usd=0, ts=? WHERE session_id='bad'", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
				t.Fatal(err)
			}
			for _, url := range []string{"/events", "/sessions/bad/timeline", "/snapshot", "/sessions/empty/timeline"} {
				w := httptest.NewRecorder()
				a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", url, nil))
				if w.Code != 200 {
					t.Fatalf("%s did not recover: %d %s", url, w.Code, w.Body.String())
				}
				if url == "/sessions/empty/timeline" && w.Body.String() != "[]\n" {
					t.Fatalf("empty history is not an array: %s", w.Body.String())
				}
			}
			h = st.WriteHealth()
			if h.ReadFailures != 3 || len(h.ReadActive) != 0 {
				t.Fatalf("incorrect read recovery: %+v", h)
			}
		})
	}
}

func TestEventEndpointsRejectClosedDatabase(t *testing.T) {
	st := testStore(t)
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	st.Close()
	for _, url := range []string{"/events", "/sessions/any/timeline"} {
		w := httptest.NewRecorder()
		a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", url, nil))
		if w.Code != 503 {
			t.Fatalf("%s hid query failure: %d %s", url, w.Code, w.Body.String())
		}
	}
}
