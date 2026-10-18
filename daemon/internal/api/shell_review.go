package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/cavi-ai/secure-agent/daemon/internal/shellreview"
)

func (a *API) handleShellReview(w http.ResponseWriter, r *http.Request) {
	a.handleShellSubmission(w, r, false)
}

func (a *API) handleShellCheck(w http.ResponseWriter, r *http.Request) {
	a.handleShellSubmission(w, r, true)
}

func (a *API) handleShellSubmission(w http.ResponseWriter, r *http.Request, check bool) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if a.shellReviews == nil {
		http.Error(w, "shell review disabled", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32768)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var req shellreview.Request
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "invalid shell observation", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		http.Error(w, "invalid shell observation", http.StatusBadRequest)
		return
	}
	var err error
	var decision shellreview.Decision
	if check {
		decision, err = a.shellReviews.Check(r.Context(), req)
	} else {
		err = a.shellReviews.Submit(req)
	}
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, shellreview.ErrQueueFull) {
			code = http.StatusTooManyRequests
		}
		if errors.Is(err, shellreview.ErrDisabled) {
			code = http.StatusServiceUnavailable
		}
		http.Error(w, "shell observation not accepted", code)
		return
	}
	if check {
		writeJSON(w, decision)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// The response explicitly describes observations, never permission decisions.
func (a *API) handleShellReviews(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	limit := 100
	if value := r.URL.Query().Get("limit"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 1000 {
			http.Error(w, "limit must be 1..1000", http.StatusBadRequest)
			return
		}
		limit = n
	}
	results, err := a.store.RecentShellReviews(limit)
	if err != nil {
		http.Error(w, "shell observations unavailable", http.StatusServiceUnavailable)
		return
	}
	health := a.shellReviews.Health()
	writeJSON(w, map[string]any{"health": health, "observations": results, "enforcement_configured": health.Mode == "block", "enforcement_scope": "hook requests to /guard/shell-check only", "authorization": "not assessed"})
}
