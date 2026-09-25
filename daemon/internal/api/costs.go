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
// harness, session, model, provider or local day, with every unpriced call
// classified. by=provider names a call with no recorded provider by the
// vendor whose price table resolves its model; by=day buckets at tz minutes
// from UTC. Read-level.
//
//	GET /costs?since=24h|7d|<RFC3339>&until=<RFC3339>&by=repo|branch|harness|session|model|provider|day&tz=<minutes>
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
		http.Error(w, "by must be one of repo, branch, harness, session, model, provider, day", http.StatusBadRequest)
		return
	}
	tz := 0
	if v := r.URL.Query().Get("tz"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < -store.MaxTZMinutes || n > store.MaxTZMinutes {
			http.Error(w, fmt.Sprintf("tz must be minutes east of UTC, -%d..%d", store.MaxTZMinutes, store.MaxTZMinutes), http.StatusBadRequest)
			return
		}
		tz = n
	}
	writeJSON(w, a.costs.get(costKey("costs", by, since, until, tz), func() any {
		rep := a.store.CostReport(since, until, by, store.CostOptions{TZMinutes: tz, ProviderFor: collect.VendorForModel})
		classifyCosts(&rep)
		return rep
	}))
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
	writeJSON(w, a.costs.get(costKey("unpriced", "harness", since, until, 0), func() any {
		return unpricedCosts(a.store.CostReport(since, until, "harness", store.CostOptions{}))
	}))
}

// unpricedCostReport is the /costs/unpriced body.
type unpricedCostReport struct {
	Since string            `json:"since"`
	Until string            `json:"until"`
	Rows  []unpricedCostRow `json:"rows"`
}

// unpricedCosts keeps the groups of rep whose calls are not priced.
func unpricedCosts(rep store.CostReport) unpricedCostReport {
	out := unpricedCostReport{Since: rep.Since, Until: rep.Until, Rows: []unpricedCostRow{}}
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
	return out
}

// handleCostsPlans serves the latest plan headroom snapshot per harness
// home, sorted by home label. Memory only: empty after a restart until the
// next line that reports it. Read-level.
//
//	GET /costs/plans
func (a *API) handleCostsPlans(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, struct {
		Plans []collect.PlanSnapshot `json:"plans"`
	}{Plans: collect.Plans()})
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

// classifyCosts splits each row's and the total's zero-cost calls by price
// class, names the class of each by=model row (priced when every call
// carries a cost, else the model's class under its dominant provider), then
// narrows unpriced_calls to the unknown-model and unpriced-model calls.
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
	for i := range rep.Rows {
		r := &rep.Rows[i]
		if rep.By == "model" {
			switch {
			case r.Unpriced == 0:
				r.Class = collect.ClassPriced
			case r.Key == "(unknown)":
				r.Class = collect.ClassUnknownModel
			default:
				r.Class = collect.Classify(r.Key, r.Provider)
			}
		}
		r.Unpriced = r.UnknownModel + r.UnpricedModel
	}
	rep.Total.Unpriced = rep.Total.UnknownModel + rep.Total.UnpricedModel
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
