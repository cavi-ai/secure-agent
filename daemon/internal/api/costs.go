package api

import (
	"cmp"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/costreport"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// handleCosts serves model-call spend over a window, grouped by repo, branch,
// harness, session, model, provider or local day, with every unpriced call
// classified. by=provider names a call with no recorded provider by the
// vendor whose price table resolves its model; by=day buckets at tz minutes
// from UTC. cached=1 answers at once from the last report for the same
// parameters, however old (also one saved by an earlier run), while a newer
// one is computed in the background (refreshing: true). Read-level.
//
//	GET /costs?since=24h|7d|<RFC3339>&until=<RFC3339>&by=repo|branch|harness|session|model|provider|day&tz=<minutes>&cached=1
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
	q := r.URL.Query()
	by := cmp.Or(q.Get("by"), "repo")
	if !store.ValidCostGroup(by) {
		http.Error(w, "by must be one of repo, branch, harness, session, model, provider, day", http.StatusBadRequest)
		return
	}
	tz := 0
	if v := q.Get("tz"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < -store.MaxTZMinutes || n > store.MaxTZMinutes {
			http.Error(w, fmt.Sprintf("tz must be minutes east of UTC, -%d..%d", store.MaxTZMinutes, store.MaxTZMinutes), http.StatusBadRequest)
			return
		}
		tz = n
	}
	key := costKey("costs", by, cmp.Or(q.Get("since"), "24h"), q.Get("until"), tz)
	rep, at, refreshing := a.costs.get(key, q.Get("cached") == "1", func() store.CostReport {
		rep := a.store.CostReport(since, until, by, store.CostOptions{TZMinutes: tz, ProviderFor: collect.VendorForModel})
		costreport.Classify(&rep)
		return rep
	})
	if at.IsZero() {
		// A cold cached request starts work without making the console wait.
		// No generated_at means these zero counters are not a computed report.
		rep.Since, rep.Until, rep.By = since.UTC().Format(time.RFC3339), until.UTC().Format(time.RFC3339), by
		rep.Rows = []store.CostRow{}
	} else {
		rep.GeneratedAt = at.UTC().Format(time.RFC3339)
	}
	rep.Refreshing = refreshing
	writeJSON(w, rep)
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
	q := r.URL.Query()
	rep, _, _ := a.unpriced.get(costKey("unpriced", "harness", cmp.Or(q.Get("since"), "24h"), q.Get("until"), 0), false,
		func() costreport.UnpricedReport {
			return costreport.Unpriced(a.store.CostReport(since, until, "harness", store.CostOptions{}))
		})
	writeJSON(w, rep)
}

// handleCostsPlans serves the newest observed quota per identified account
// and limit. Per-home snapshots remain available for durable restoration.
//
//	GET /costs/plans
func (a *API) handleCostsPlans(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, struct {
		Plans []collect.PlanSnapshot `json:"plans"`
	}{Plans: collect.AccountPlans()})
}

// costWindow reads since (default 24h ago) and until (default now).
func costWindow(r *http.Request) (since, until time.Time, err error) {
	q := r.URL.Query()
	now := time.Now()
	since, until = now.Add(-24*time.Hour), now
	if v := q.Get("since"); v != "" {
		if since, err = costreport.ParseSince(v, now); err != nil {
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
