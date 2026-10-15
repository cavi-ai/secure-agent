package api

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func (a *API) serveHookEvidence(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q, parseErr := url.ParseQuery(r.URL.RawQuery)
	if parseErr != nil {
		http.Error(w, "invalid hook evidence filters", http.StatusBadRequest)
		return
	}
	for key, values := range q {
		if len(values) != 1 {
			http.Error(w, "invalid hook evidence filters", http.StatusBadRequest)
			return
		}
		switch key {
		case "harness", "event", "event_scope", "handler_id", "config_id", "script", "verify_after":
		default:
			http.Error(w, "invalid hook evidence filters", http.StatusBadRequest)
			return
		}
	}
	f := store.HookEvidenceFilter{Harness: q.Get("harness"), Event: q.Get("event"), EventScope: q.Get("event_scope"), HandlerID: q.Get("handler_id"), ConfigID: q.Get("config_id"), Script: q.Get("script")}
	if value, ok := q["verify_after"]; ok {
		after, err := time.Parse(time.RFC3339Nano, value[0])
		if err != nil {
			http.Error(w, "invalid hook evidence filters", http.StatusBadRequest)
			return
		}
		f.VerifyAfter = &after
	}
	page, err := a.store.SessionHookEvidence(id, f, time.Now().UTC())
	if err != nil {
		if errors.Is(err, store.ErrHookEvidenceQuery) {
			http.Error(w, "invalid hook evidence filters", http.StatusBadRequest)
		} else {
			http.Error(w, "hook evidence unavailable", http.StatusServiceUnavailable)
		}
		return
	}
	writeJSON(w, page)
}
