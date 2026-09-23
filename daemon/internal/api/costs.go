package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// handleCosts serves model-call spend over a window, grouped by repo, branch,
// harness, session or model, with every unpriced call classified. Read-level.
//
//	GET /costs?since=24h|7d|<RFC3339>&until=<RFC3339>&by=repo|branch|harness|session|model
func (a *API) handleCosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	since, until, err := costWindow(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	by := r.URL.Query().Get("by")
	if by == "" {
		by = "repo"
	}
	if !store.ValidCostGroup(by) {
		http.Error(w, "by must be one of repo, branch, harness, session, model", http.StatusBadRequest)
		return
	}
	rep := a.store.CostReport(since, until, by)
	classifyCosts(&rep)
	writeJSON(w, rep)
}

// unpricedCostRow is one (harness, provider, model) whose calls carry no
// cost, with the reason.
type unpricedCostRow struct {
	Harness   string `json:"harness"`
	Provider  string `json:"provider"`
	Model     string `json:"model"`
	Class     string `json:"class"`
	Calls     int    `json:"calls"`
	TokensIn  int64  `json:"tokens_in"`
	TokensOut int64  `json:"tokens_out"`
}

// handleCostsUnpriced lists the model calls that carry no cost, by harness,
// provider and model, with their price class; zero-token calls of a priced
// model are left out. Read-level.
//
//	GET /costs/unpriced?since=24h|7d|<RFC3339>&until=<RFC3339>
func (a *API) handleCostsUnpriced(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	since, until, err := costWindow(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rep := a.store.CostReport(since, until, "harness")
	out := struct {
		Since string            `json:"since"`
		Until string            `json:"until"`
		Rows  []unpricedCostRow `json:"rows"`
	}{Since: rep.Since, Until: rep.Until, Rows: []unpricedCostRow{}}
	for _, g := range rep.Groups {
		class := collect.Classify(g.Model, g.Provider)
		if class == collect.ClassPriced {
			continue
		}
		out.Rows = append(out.Rows, unpricedCostRow{
			Harness: g.Key, Provider: g.Provider, Model: g.Model, Class: class,
			Calls: g.Calls, TokensIn: g.TokensIn, TokensOut: g.TokensOut,
		})
	}
	writeJSON(w, out)
}

// costWindow reads since (default 24h ago) and until (default now).
func costWindow(r *http.Request) (since, until time.Time, err error) {
	q := r.URL.Query()
	now := time.Now()
	since, until = now.Add(-24*time.Hour), now
	if v := q.Get("since"); v != "" {
		if since, err = parseSince(v, now); err != nil {
			return since, until, err
		}
	}
	if v := q.Get("until"); v != "" {
		if until, err = time.Parse(time.RFC3339, v); err != nil {
			return since, until, fmt.Errorf("until must be an RFC3339 timestamp")
		}
	}
	return since, until, nil
}

// classifyCosts splits each row's and the total's unpriced calls by price
// class, and names the class of each by=model row: priced when every call
// carries a cost, else the model's class under its dominant provider.
func classifyCosts(rep *store.CostReport) {
	idx := make(map[string]int, len(rep.Rows))
	for i, r := range rep.Rows {
		idx[r.Key] = i
	}
	for _, g := range rep.Groups {
		class := collect.Classify(g.Model, g.Provider)
		addPriceClass(&rep.Total, class, g.Calls)
		if i, ok := idx[g.Key]; ok {
			addPriceClass(&rep.Rows[i], class, g.Calls)
		}
	}
	if rep.By != "model" {
		return
	}
	for i := range rep.Rows {
		r := &rep.Rows[i]
		switch {
		case r.Unpriced == 0:
			r.Class = collect.ClassPriced
		case r.Key == "(unknown)":
			r.Class = collect.ClassUnknownModel
		default:
			r.Class = collect.Classify(r.Key, r.Provider)
		}
	}
}

func addPriceClass(r *store.CostRow, class string, n int) {
	switch class {
	case collect.ClassUnknownModel:
		r.UnknownModel += n
	case collect.ClassUnpricedModel:
		r.UnpricedModel += n
	case collect.ClassPlan:
		r.Plan += n
	case collect.ClassLocal:
		r.Local += n
	}
}

// parseSince accepts a lookback ("24h", "90m", "7d") or an RFC3339
// timestamp. Shared by /costs and /sessions.
func parseSince(v string, now time.Time) (time.Time, error) {
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
