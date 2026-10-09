package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func (a *API) handleReviews(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	q := r.URL.Query()
	state := q.Get("state")
	if state != "" && state != "unreviewed" && state != "reviewed" && state != "closed_reported" {
		http.Error(w, "Invalid review state", 400)
		return
	}
	page, err := a.store.ListFindingReviewsState(q.Get("after"), min(queryInt(q.Get("limit"), 100), 100), state)
	if err != nil {
		http.Error(w, "review data unavailable; source findings remain available", 503)
		return
	}
	writeJSON(w, page)
}

func (a *API) handleReviewDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	limitBody(w, r)
	var req model.ReviewDecisionRequest
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&req); err != nil || !guardTokenRE.MatchString(req.ID) || req.Revision < 1 || (req.Action != "acknowledge" && req.Action != "close_reported" && req.Action != "expect") ||
		(req.Action == "expect" && (req.Scope == nil || req.Scope.Validate() != nil)) || (req.Action != "expect" && req.Scope != nil) {
		http.Error(w, "Invalid review decision", 400)
		return
	}
	receipt, err := a.store.DecideFindingReview(req)
	switch {
	case errors.Is(err, store.ErrReviewConflict):
		http.Error(w, "Evidence changed. Refresh and choose again.", 409)
	case errors.Is(err, store.ErrReviewMissing):
		http.Error(w, "Review evidence unavailable", 404)
	case err != nil:
		http.Error(w, "Decision could not be saved", 503)
	default:
		if a.deltaHub != nil {
			a.deltaHub.Publish(Delta{Type: "review", Data: receipt})
		}
		writeJSON(w, receipt)
	}
}
