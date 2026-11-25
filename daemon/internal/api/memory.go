package api

import (
	"net/http"
	"strconv"

	"github.com/cavi-ai/secure-agent/daemon/internal/report"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type memoryRow report.MemoryRow

type memoryResponse struct {
	Rows       []memoryRow `json:"rows"`
	HasEarlier bool        `json:"has_earlier"`
	NextCursor string      `json:"next_cursor,omitempty"`
}

func (a *API) serveSessionMemory(w http.ResponseWriter, r *http.Request, id string) {
	_, ok, err := a.store.GetSessionBounded(id)
	if err != nil {
		http.Error(w, "session data unavailable", http.StatusServiceUnavailable)
		return
	}
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	q := r.URL.Query()
	limit := 200
	if values, ok := q["limit"]; ok {
		if len(values) != 1 {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
		n, err := strconv.Atoi(values[0])
		if err != nil || n < 1 {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
		if n > 500 {
			n = 500
		}
		limit = n
	}
	var before *store.MemoryCursor
	if values, ok := q["before"]; ok {
		if len(values) != 1 {
			http.Error(w, "invalid cursor", http.StatusBadRequest)
			return
		}
		var err error
		before, err = report.DecodeMemoryCursor(values[0])
		if err != nil {
			http.Error(w, "invalid cursor", http.StatusBadRequest)
			return
		}
	}
	response, err := sessionMemory(a.store, id, before, limit)
	if err != nil {
		http.Error(w, "memory unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, response)
}
