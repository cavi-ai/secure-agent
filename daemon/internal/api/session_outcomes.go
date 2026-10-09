package api

import (
	"net/http"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type SessionOutcomes struct {
	SessionID  string                      `json:"session_id"`
	ObservedAt time.Time                   `json:"observed_at"`
	History    store.SessionOutcomeHistory `json:"history"`
}

// serveSessionOutcomes reads receipts without scanning the session's activity.
func (a *API) serveSessionOutcomes(w http.ResponseWriter, r *http.Request, id string) {
	_, found, err := a.store.GetSessionResult(id)
	if err != nil {
		http.Error(w, "session results unavailable", http.StatusServiceUnavailable)
		return
	}
	if !found {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	writeJSON(w, SessionOutcomes{SessionID: id, ObservedAt: time.Now().UTC(), History: a.store.SessionOutcomes(id)})
}
