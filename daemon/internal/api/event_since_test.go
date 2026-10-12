package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestEventsEndpointHonorsNanosecondSince(t *testing.T) {
	st := testStore(t)
	cutoff := "2026-10-11T13:00:00.123456789+01:00"
	at, err := time.Parse(time.RFC3339Nano, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		label string
		ts    time.Time
	}{
		{"before", at.Add(-time.Nanosecond)}, {"at", at}, {"after", at.Add(time.Nanosecond)},
	} {
		if _, err := st.PutEvent(event.Event{Kind: event.KindFileOpen, TS: row.ts, Detail: row.label, SessionID: "owned"}); err != nil {
			t.Fatal(err)
		}
	}
	a := newTestAPI(Deps{Store: st, Killer: &fakeKiller{}, Status: func() Status { return Status{Running: true} }})
	query := url.Values{"since": {cutoff}, "session_id": {"owned"}}
	get := func(target any) {
		t.Helper()
		w := httptest.NewRecorder()
		a.handleEvents(w, httptest.NewRequest(http.MethodGet, "/events?"+query.Encode(), nil))
		if w.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		if err := json.Unmarshal(w.Body.Bytes(), target); err != nil {
			t.Fatal(err)
		}
	}
	var rows []event.Event
	get(&rows)
	if len(rows) != 2 || rows[0].Detail != "after" || rows[1].Detail != "at" {
		t.Fatalf("events=%v", rows)
	}
	query.Set("page", "1")
	query.Set("limit", "1")
	var first EventPage
	get(&first)
	if len(first.Rows) != 1 || first.Rows[0].Event.Detail != "after" || !first.HasEarlier || first.NextCursor == "" {
		t.Fatalf("first page=%+v", first)
	}
	query.Set("before", first.NextCursor)
	var last EventPage
	get(&last)
	if len(last.Rows) != 1 || last.Rows[0].Event.Detail != "at" || last.HasEarlier || last.NextCursor != "" {
		t.Fatalf("last page=%+v", last)
	}
}
