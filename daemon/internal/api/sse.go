package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// handleEventStream is the SSE live feed: one persistent connection per
// console, every bus event pushed as it happens — replaces the 2 s poll.
// Events arrive on the shared bus; this handler only fans them out.
//
// The API listens on a 0600 unix socket, so the feed inherits that boundary:
// anything that can read it can already read every other endpoint.
func (a *API) handleEventStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.subscribeEvents == nil {
		http.Error(w, "event stream not enabled", http.StatusServiceUnavailable)
		return
	}

	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, ": secure-agent event stream\n\n")
	fl.Flush()

	sub := a.subscribeEvents()
	defer func() {
		if a.unsubscribeEvents != nil {
			a.unsubscribeEvents(sub)
		}
	}()

	// Heartbeat keeps proxies/middleboxes from idling the connection out and
	// gives the client a liveness signal.
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case e, ok := <-sub:
			if !ok {
				return
			}
			data, err := json.Marshal(e)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Kind.String(), data)
			fl.Flush()
		case <-heartbeat.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		}
	}
}

// SetEventStream wires the bus subscription factory. subscribe must be safe
// for concurrent use; release unsubscribes (the API package cannot import bus
// internals directly from handlers without a cycle-safe seam).
func (a *API) SetEventStream(subscribe func() <-chan event.Event, release func(<-chan event.Event)) {
	a.subscribeEvents = subscribe
	a.unsubscribeEvents = release
}
