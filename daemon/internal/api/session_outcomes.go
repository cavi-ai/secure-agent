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
	FollowUp   SessionFollowUp             `json:"follow_up"`
}

// serveSessionOutcomes reads receipts without scanning the session's activity.
func (a *API) serveSessionOutcomes(w http.ResponseWriter, r *http.Request, id string) {
	history, found, err := a.store.SessionOutcomeContext(r.Context(), id)
	if err != nil {
		http.Error(w, "session results unavailable", http.StatusServiceUnavailable)
		return
	}
	if !found {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	observedAt := time.Now().UTC()
	writeJSON(w, SessionOutcomes{SessionID: id, ObservedAt: observedAt, History: history, FollowUp: buildSessionFollowUp(id, observedAt, history)})
}
