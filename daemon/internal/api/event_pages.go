package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type recordedEventRow struct {
	ID    string      `json:"id"`
	Event event.Event `json:"event"`
}

type EventPage struct {
	SessionID  string             `json:"session_id"`
	Rows       []recordedEventRow `json:"rows"`
	HasEarlier bool               `json:"has_earlier"`
	NextCursor string             `json:"next_cursor,omitempty"`
}

type eventCursor struct {
	Version   int    `json:"v"`
	Before    string `json:"before"`
	SessionID string `json:"session"`
	Kind      string `json:"kind"`
	PID       int32  `json:"pid"`
	Since     string `json:"since"`
}

func (a *API) serveEventPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for _, name := range []string{"page", "session_id", "kind", "pid", "since", "limit", "before"} {
		if len(q[name]) > 1 {
			http.Error(w, "duplicate event page parameter", http.StatusBadRequest)
			return
		}
	}
	if q.Get("page") != "1" || q.Get("session_id") == "" || len(q.Get("session_id")) > 512 {
		http.Error(w, "event page requires a session", http.StatusBadRequest)
		return
	}
	f := store.EventFilter{SessionID: q.Get("session_id"), Since: q.Get("since"), Limit: 200}
	for _, name := range []string{"kind", "pid", "limit"} {
		if raw, present := q[name]; present {
			n, err := strconv.ParseInt(raw[0], 10, 32)
			if err != nil || n < 0 || (name == "limit" && n == 0) {
				http.Error(w, "invalid event page filter", http.StatusBadRequest)
				return
			}
			switch name {
			case "kind":
				k := int(n)
				f.Kind = &k
			case "pid":
				f.PID = int32(n)
			case "limit":
				f.Limit = min(int(n), 200)
			}
		}
	}
	if f.Since != "" {
		at, err := time.Parse(time.RFC3339Nano, f.Since)
		if err != nil {
			http.Error(w, "invalid event page time", http.StatusBadRequest)
			return
		}
		f.Since = at.UTC().Format(time.RFC3339Nano)
	}
	scope := eventCursor{Version: 1, SessionID: f.SessionID, PID: f.PID, Since: f.Since}
	if f.Kind != nil {
		scope.Kind = strconv.Itoa(*f.Kind)
	}
	var beforeID int64
	if raw, present := q["before"]; present {
		var cursor eventCursor
		if len(raw[0]) > 2048 {
			http.Error(w, "invalid event cursor", http.StatusBadRequest)
			return
		}
		decoded, err := base64.RawURLEncoding.DecodeString(raw[0])
		if err != nil || json.Unmarshal(decoded, &cursor) != nil {
			http.Error(w, "invalid event cursor", http.StatusBadRequest)
			return
		}
		beforeID, err = strconv.ParseInt(cursor.Before, 10, 64)
		cursor.Before = ""
		if err != nil || beforeID <= 0 || cursor != scope {
			http.Error(w, "event cursor does not match filters", http.StatusBadRequest)
			return
		}
	}
	rows, earlier, err := a.store.QueryRecordedEvents(f, beforeID)
	if err != nil {
		http.Error(w, "event data unavailable", http.StatusServiceUnavailable)
		return
	}
	page := EventPage{SessionID: f.SessionID, Rows: []recordedEventRow{}, HasEarlier: earlier}
	for _, row := range rows {
		e := priceClassed([]event.Event{row.Event})[0]
		page.Rows = append(page.Rows, recordedEventRow{ID: strconv.FormatInt(row.ID, 10), Event: e})
	}
	if earlier && len(rows) > 0 {
		scope.Before = strconv.FormatInt(rows[len(rows)-1].ID, 10)
		encoded, _ := json.Marshal(scope)
		page.NextCursor = base64.RawURLEncoding.EncodeToString(encoded)
	}
	writeJSON(w, page)
}
