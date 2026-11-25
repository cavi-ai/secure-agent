package api

import (
	"log"
	"net/http"
	"time"
)

type stopIntentReceipt struct {
	RecordedAt string `json:"recorded_at"`
	ValidUntil string `json:"valid_until"`
}

// handleStopIntent records that the owner is about to stop the daemon: a
// SIGTERM before valid_until ends the run as an owner stop.
func (a *API) handleStopIntent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.stopIntent == nil {
		http.Error(w, "stop intent unavailable", http.StatusServiceUnavailable)
		return
	}
	at, until, err := a.stopIntent()
	if err != nil {
		log.Printf("api: stop intent not recorded: %v", err)
		http.Error(w, "stop intent not recorded", http.StatusInternalServerError)
		return
	}
	writeJSON(w, stopIntentReceipt{RecordedAt: at.UTC().Format(time.RFC3339Nano), ValidUntil: until.UTC().Format(time.RFC3339Nano)})
}
