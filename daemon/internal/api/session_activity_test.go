package api

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
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

func TestSessionEventPagesRetainScopeAcrossNewWrites(t *testing.T) {
	st := testStore(t)
	at := time.Now().UTC()
	for i := 0; i < 7; i++ {
		if _, err := st.PutEvent(event.Event{Kind: event.KindFileOpen, TS: at, SessionID: "ended", Path: fmt.Sprintf("/retained/%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	query := "/events?page=1&session_id=ended&kind=0&limit=3"
	read := func(path string) map[string]any {
		t.Helper()
		w := httptest.NewRecorder()
		a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	page := read(query)
	seen := map[string]bool{}
	for batch := 0; ; batch++ {
		rows := page["rows"].([]any)
		for _, raw := range rows {
			row := raw.(map[string]any)
			id, ok := row["id"].(string)
			if !ok || id == "" || seen[id] {
				t.Fatalf("missing/duplicate durable row identity: %+v", row)
			}
			seen[id] = true
			e := row["event"].(map[string]any)
			if e["session_id"] != "ended" || e["kind"] != float64(0) || e["path"] == "/new" {
				t.Fatalf("page drifted into newer or foreign records: %+v", e)
			}
		}
		cursor, _ := page["next_cursor"].(string)
		if cursor == "" {
			if page["has_earlier"] != false || len(rows) != 1 || len(seen) != 7 {
				t.Fatalf("last page lost records: %+v seen=%d", page, len(seen))
			}
			break
		}
		if batch == 0 {
			for _, row := range []event.Event{
				{Kind: event.KindFileOpen, TS: at, SessionID: "ended", Path: "/new"},
				{Kind: event.KindFileOpen, TS: at, SessionID: "other", Path: "/foreign"},
			} {
				if _, err := st.PutEvent(row); err != nil {
					t.Fatal(err)
				}
			}
			for key, value := range map[string]string{"session_id": "other", "kind": "5", "pid": "1", "since": at.Format(time.RFC3339Nano)} {
				params, err := url.ParseQuery(query[len("/events?"):])
				if err != nil {
					t.Fatal(err)
				}
				params.Set("before", cursor)
				params.Set(key, value)
				w := httptest.NewRecorder()
				a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/events?"+params.Encode(), nil))
				if w.Code != 400 {
					t.Fatalf("changed cursor scope accepted: %s HTTP %d", key, w.Code)
				}
			}
		}
		page = read(query + "&before=" + url.QueryEscape(cursor))
	}
}

func TestSessionEventPageRejectsInvalidRequests(t *testing.T) {
	a := newTestAPI("", testStore(t), nil, func() Status { return Status{Running: true} })
	for _, query := range []string{"page=1", "page=bad&session_id=s", "page=1&session_id=s&before=bad", "page=1&session_id=s&limit=0", "page=1&session_id=s&kind=bad", "page=1&session_id=s&since=bad"} {
		w := httptest.NewRecorder()
		a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/events?"+query, nil))
		if w.Code != 400 {
			t.Errorf("%s: HTTP %d", query, w.Code)
		}
	}
}
