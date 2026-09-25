package store

import (
	"fmt"
	"log"
	"maps"
	"slices"
	"strings"
	"time"
)

// CostRow is one group of model calls in a CostReport.
type CostRow struct {
	Key       string  `json:"key"`                // group value: repo | harness | session id | model | repo@branch | provider | YYYY-MM-DD
	Harness   string  `json:"harness,omitempty"`  // harness with the most calls in the group (empty for by=harness)
	Provider  string  `json:"provider,omitempty"` // by=model: provider with the most calls for the model
	Class     string  `json:"class,omitempty"`    // by=model: price class, set by the API from the pricing tables
	Calls     int     `json:"calls"`
	Sessions  int     `json:"sessions"` // distinct session ids in the group
	TokensIn  int64   `json:"tokens_in"`
	TokensOut int64   `json:"tokens_out"`
	CostUSD   float64 `json:"cost_usd"`
	Unpriced  int     `json:"unpriced_calls"` // calls with cost 0 as read; /costs narrows it to unknown-model + unpriced-model
	// Why the unpriced calls carry no cost, set by the API from Groups.
	UnknownModel  int `json:"unknown_model_calls"`  // no model id recorded
	UnpricedModel int `json:"unpriced_model_calls"` // model id with no price entry
	Plan          int `json:"plan_calls"`           // subscription provider
	Local         int `json:"local_calls"`          // local runtime
}

// CostReport is model-call spend over a window, grouped by one dimension.
type CostReport struct {
	Since string    `json:"since"`
	Until string    `json:"until"`
	By    string    `json:"by"`
	Total CostRow   `json:"total"` // Key ""; Sessions = distinct sessions overall
	Rows  []CostRow `json:"rows"`  // cost desc, then calls desc (by=day: day asc); at most costRowLimit; never nil
	// Groups is every zero-cost call bucketed by (group key, model,
	// provider), read in the same pass as Rows, for the API to classify.
	Groups []UnpricedGroup `json:"-"`
}

// UnpricedGroup counts the zero-cost model calls of one (group key, model,
// provider). Model and Provider are raw ("" when not recorded).
type UnpricedGroup struct {
	Key       string
	Model     string
	Provider  string
	Calls     int
	TokensIn  int64
	TokensOut int64
}

const costRowLimit = 200

// CostOptions carries the inputs of the day and provider groupings.
type CostOptions struct {
	// TZMinutes is the local offset from UTC in minutes (east positive) that
	// by=day buckets in; outside ±MaxTZMinutes it is taken as 0.
	TZMinutes int
	// ProviderFor names the vendor of a model id for by=provider calls with
	// no recorded provider; nil, or "" for an id, leaves them (unknown).
	ProviderFor func(model string) string
}

// MaxTZMinutes bounds CostOptions.TZMinutes: UTC-14:00 to UTC+14:00.
const MaxTZMinutes = 840

// maxProviderModels caps the model ids bound into the by=provider key; ids
// past the cap group as (unknown).
const maxProviderModels = 500

// costGroupExprs maps each fixed grouping to its SQL key expression over
// events e LEFT JOIN sessions s. day and provider are built per report.
var costGroupExprs = map[string]string{
	"repo":    `COALESCE(NULLIF(s.repo,''),'(no repo)')`,
	"branch":  `COALESCE(NULLIF(s.repo,''),'(no repo)') || '@' || COALESCE(NULLIF(s.branch,''),'(no branch)')`,
	"harness": `COALESCE(NULLIF(s.harness,''),'(unknown)')`,
	"session": `COALESCE(e.session_id,'')`,
	"model":   `COALESCE(NULLIF(e.model,''),'(unknown)')`,
}

// ValidCostGroup reports whether by is a supported CostReport grouping.
func ValidCostGroup(by string) bool {
	_, ok := costGroupExprs[by]
	return ok || by == "day" || by == "provider"
}

// costFrom leaves out `<synthetic>` rows: Claude Code's zero-usage internal
// turns, recorded as model calls before ingest dropped them.
const costFrom = ` FROM events e LEFT JOIN sessions s ON s.id = e.session_id
	WHERE e.kind = 14 AND COALESCE(e.model,'') != '<synthetic>'
	AND datetime(e.ts) >= datetime(?) AND datetime(e.ts) < datetime(?)`

// CostReport sums model calls (kind 14) in [since, until) grouped by repo,
// branch, harness, session, model, provider or local day. An unknown grouping
// falls back to repo.
func (s *Store) CostReport(since, until time.Time, by string, opts CostOptions) CostReport {
	if !ValidCostGroup(by) {
		by = "repo"
	}
	sinceStr := since.UTC().Format(time.RFC3339Nano)
	untilStr := until.UTC().Format(time.RFC3339Nano)
	rep := CostReport{
		Since: since.UTC().Format(time.RFC3339),
		Until: until.UTC().Format(time.RFC3339),
		By:    by,
		Rows:  []CostRow{},
	}
	const aggregates = `COUNT(*), COUNT(DISTINCT NULLIF(e.session_id,'')),
		COALESCE(SUM(e.tokens_in),0), COALESCE(SUM(e.tokens_out),0), COALESCE(SUM(e.cost_usd),0),
		COALESCE(SUM(CASE WHEN e.cost_usd IS NULL OR e.cost_usd = 0 THEN 1 ELSE 0 END),0)`

	keyExpr, keyArgs := costGroupExprs[by], []any(nil)
	switch by {
	case "day":
		keyExpr = costDayExpr(opts.TZMinutes)
	case "provider":
		// ProviderFor is caller code: it runs with s.mu released.
		keyExpr, keyArgs = costProviderExpr(opts.ProviderFor, s.costProviderModels(opts.ProviderFor, sinceStr, untilStr))
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	windowArgs := func(extra ...any) []any {
		return append(append(slices.Clone(keyArgs), sinceStr, untilStr), extra...)
	}

	t := &rep.Total
	if err := s.db.QueryRow(`SELECT `+aggregates+costFrom, sinceStr, untilStr).
		Scan(&t.Calls, &t.Sessions, &t.TokensIn, &t.TokensOut, &t.CostUSD, &t.Unpriced); err != nil {
		log.Printf("store: cost total error: %v", err)
		return rep
	}

	order := `6 DESC, 2 DESC, k ASC`
	if by == "day" {
		order = `k DESC` // the newest days under the limit, reversed below
	}
	rows, err := s.db.Query(`SELECT `+keyExpr+` AS k, `+aggregates+costFrom+`
		GROUP BY k ORDER BY `+order+` LIMIT ?`, windowArgs(costRowLimit)...)
	if err != nil {
		log.Printf("store: cost report error: %v", err)
		return rep
	}
	for rows.Next() {
		var r CostRow
		if err := rows.Scan(&r.Key, &r.Calls, &r.Sessions, &r.TokensIn, &r.TokensOut, &r.CostUSD, &r.Unpriced); err == nil {
			rep.Rows = append(rep.Rows, r)
		}
	}
	rows.Close()
	if by == "day" {
		slices.Reverse(rep.Rows)
	}

	grows, err := s.db.Query(`SELECT `+keyExpr+` AS k, COALESCE(e.model,'') AS m, COALESCE(e.provider,'') AS p,
		COUNT(*), COALESCE(SUM(e.tokens_in),0), COALESCE(SUM(e.tokens_out),0)`+costFrom+`
		AND (e.cost_usd IS NULL OR e.cost_usd = 0)
		GROUP BY k, m, p ORDER BY 4 DESC, k, m, p`, windowArgs()...)
	if err != nil {
		log.Printf("store: cost unpriced groups error: %v", err)
	} else {
		for grows.Next() {
			var g UnpricedGroup
			if err := grows.Scan(&g.Key, &g.Model, &g.Provider, &g.Calls, &g.TokensIn, &g.TokensOut); err == nil {
				rep.Groups = append(rep.Groups, g)
			}
		}
		if err := grows.Err(); err != nil {
			log.Printf("store: cost unpriced groups cursor error: %v", err)
		}
		grows.Close()
	}

	if len(rep.Rows) == 0 {
		return rep
	}
	if by != "harness" {
		harness := s.dominantLocked(keyExpr, "s.harness", windowArgs())
		for i := range rep.Rows {
			rep.Rows[i].Harness = harness[rep.Rows[i].Key]
		}
	}
	if by == "model" {
		provider := s.dominantLocked(keyExpr, "e.provider", windowArgs())
		for i := range rep.Rows {
			rep.Rows[i].Provider = provider[rep.Rows[i].Key]
		}
	}
	return rep
}

// costDayExpr keys a call by its local calendar day, YYYY-MM-DD, at
// tzMinutes from UTC.
func costDayExpr(tzMinutes int) string {
	if tzMinutes < -MaxTZMinutes || tzMinutes > MaxTZMinutes {
		tzMinutes = 0
	}
	return fmt.Sprintf(`substr(datetime(e.ts,'%+d minutes'),1,10)`, tzMinutes)
}

// costProviderModels lists the distinct model ids in the window with no
// recorded provider, or nil when providerFor is nil. It takes s.mu.
func (s *Store) costProviderModels(providerFor func(string) string, sinceStr, untilStr string) []string {
	if providerFor == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT DISTINCT COALESCE(e.model,'') AS m`+costFrom+`
		AND COALESCE(e.provider,'') = '' ORDER BY m`, sinceStr, untilStr)
	if err != nil {
		log.Printf("store: cost provider models error: %v", err)
		return nil
	}
	defer rows.Close()
	var models []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err == nil && m != "" {
			models = append(models, m)
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("store: cost provider models cursor error: %v", err)
	}
	return models
}

// costProviderExpr builds the by=provider key: the recorded provider, else
// the vendor providerFor names for the model id, else (unknown). Model ids
// and vendors are bound parameters, returned with the expression. It calls
// providerFor and must run without s.mu held.
func costProviderExpr(providerFor func(string) string, models []string) (string, []any) {
	const recorded = `CASE WHEN NULLIF(e.provider,'') IS NOT NULL THEN e.provider`
	const unknown = ` ELSE '(unknown)' END`
	if providerFor == nil {
		return recorded + unknown, nil
	}
	byVendor := map[string][]any{}
	bound := 0
	for _, m := range models {
		if bound >= maxProviderModels {
			break
		}
		if v := providerFor(m); v != "" {
			byVendor[v] = append(byVendor[v], m)
			bound++
		}
	}

	var b strings.Builder
	b.WriteString(recorded)
	var args []any
	for _, v := range slices.Sorted(maps.Keys(byVendor)) {
		ms := byVendor[v]
		b.WriteString(` WHEN e.model IN (?` + strings.Repeat(`,?`, len(ms)-1) + `) THEN ?`)
		args = append(append(args, ms...), v)
	}
	b.WriteString(unknown)
	return b.String(), args
}

// dominantLocked maps each group key to the non-empty value of col with the
// most calls in the window; ties break alphabetically. args binds keyExpr's
// parameters, then the window. Caller holds s.mu.
func (s *Store) dominantLocked(keyExpr, col string, args []any) map[string]string {
	dominant := map[string]string{}
	rows, err := s.db.Query(`SELECT `+keyExpr+` AS k, `+col+` AS v, COUNT(*) AS n`+costFrom+`
		AND `+col+` IS NOT NULL AND `+col+` != ''
		GROUP BY k, v ORDER BY k, n DESC, v ASC`, args...)
	if err != nil {
		log.Printf("store: cost dominant %s error: %v", col, err)
		return dominant
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		var n int
		if err := rows.Scan(&k, &v, &n); err == nil {
			if _, seen := dominant[k]; !seen {
				dominant[k] = v
			}
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("store: cost dominant %s cursor error: %v", col, err)
	}
	return dominant
}
