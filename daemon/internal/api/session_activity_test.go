package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestSessionEventsAreFilteredBeforeTheHistoryLimit(t *testing.T) {
	st := testStore(t)
	now := time.Now().UTC()
	for _, row := range []event.Event{
		{Kind: event.KindFileOpen, TS: now.Add(-2 * time.Hour), SessionID: "ended-session", Path: "/workspace/earlier.go"},
		{Kind: event.KindFileOpen, TS: now.Add(-time.Hour), SessionID: "ended-session", Path: "/workspace/latest.go"},
		{Kind: event.KindProxyHit, TS: now, SessionID: "other-session", RemoteHost: "example.invalid"},
		{Kind: event.KindFileOpen, TS: now, Path: "/workspace/unattributed.go"},
	} {
		if _, err := st.PutEvent(row); err != nil {
			t.Fatal(err)
		}
	}
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	for _, tc := range []struct {
		query string
		path  string
	}{
		{"session_id=ended-session&limit=1", "/workspace/latest.go"},
		{"session_id=ended-session&kind=0&since=" + now.Add(-90*time.Minute).Format(time.RFC3339) + "&limit=1", "/workspace/latest.go"},
		{"session_id=unknown-session&limit=1", ""},
	} {
		t.Run(tc.query, func(t *testing.T) {
			w := httptest.NewRecorder()
			a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/events?"+tc.query, nil))
			if w.Code != 200 {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			var rows []event.Event
			if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
				t.Fatal(err)
			}
			if tc.path == "" {
				if len(rows) != 0 {
					t.Fatalf("unknown session fell back to global events: %+v", rows)
				}
			} else if len(rows) != 1 || rows[0].SessionID != "ended-session" || rows[0].Path != tc.path {
				t.Fatalf("session history was filtered after limiting: %+v", rows)
			}
		})
	}
}
