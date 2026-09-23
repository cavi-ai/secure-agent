package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// handleCosts serves model-call spend over a window, grouped by repo, branch,
// harness, session or model. Read-level.
//
//	GET /costs?since=24h|7d|<RFC3339>&until=<RFC3339>&by=repo|branch|harness|session|model
func (a *API) handleCosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	now := time.Now()
	since := now.Add(-24 * time.Hour)
	if v := q.Get("since"); v != "" {
		t, err := parseCostSince(v, now)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		since = t
	}
	until := now
	if v := q.Get("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			http.Error(w, "until must be an RFC3339 timestamp", http.StatusBadRequest)
			return
		}
		until = t
	}
	by := q.Get("by")
	if by == "" {
		by = "repo"
	}
	if !store.ValidCostGroup(by) {
		http.Error(w, "by must be one of repo, branch, harness, session, model", http.StatusBadRequest)
		return
	}
	writeJSON(w, a.store.CostReport(since, until, by))
}

// parseCostSince accepts a lookback ("24h", "90m", "7d") or an RFC3339
// timestamp.
func parseCostSince(v string, now time.Time) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	if days, ok := strings.CutSuffix(v, "d"); ok {
		if n, err := strconv.Atoi(days); err == nil && n > 0 {
			return now.Add(-time.Duration(n) * 24 * time.Hour), nil
		}
	} else if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return now.Add(-d), nil
	}
	return time.Time{}, fmt.Errorf("since must be a positive lookback (24h, 7d) or an RFC3339 timestamp")
}
