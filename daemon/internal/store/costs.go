package store

import (
	"log"
	"time"
)

// CostRow is one group of model calls in a CostReport.
type CostRow struct {
	Key       string  `json:"key"`               // group value: repo | harness | session id | model | repo@branch
	Harness   string  `json:"harness,omitempty"` // harness with the most calls in the group (empty for by=harness)
	Calls     int     `json:"calls"`
	Sessions  int     `json:"sessions"` // distinct session ids in the group
	TokensIn  int64   `json:"tokens_in"`
	TokensOut int64   `json:"tokens_out"`
	CostUSD   float64 `json:"cost_usd"`
	Unpriced  int     `json:"unpriced_calls"` // calls with cost 0 (unknown model); never assigned a price
}

// CostReport is model-call spend over a window, grouped by one dimension.
type CostReport struct {
	Since string    `json:"since"`
	Until string    `json:"until"`
	By    string    `json:"by"`
	Total CostRow   `json:"total"` // Key ""; Sessions = distinct sessions overall
	Rows  []CostRow `json:"rows"`  // cost desc, then calls desc; at most costRowLimit; never nil
}

const costRowLimit = 200

// costGroupExprs maps each supported grouping to its SQL key expression over
// events e LEFT JOIN sessions s.
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
	return ok
}

const costFrom = ` FROM events e LEFT JOIN sessions s ON s.id = e.session_id
	WHERE e.kind = 14 AND datetime(e.ts) >= datetime(?) AND datetime(e.ts) < datetime(?)`

// CostReport sums model calls (kind 14) in [since, until) grouped by repo,
// branch, harness, session or model. An unknown grouping falls back to repo.
func (s *Store) CostReport(since, until time.Time, by string) CostReport {
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
	keyExpr := costGroupExprs[by]
	const aggregates = `COUNT(*), COUNT(DISTINCT NULLIF(e.session_id,'')),
		COALESCE(SUM(e.tokens_in),0), COALESCE(SUM(e.tokens_out),0), COALESCE(SUM(e.cost_usd),0),
		COALESCE(SUM(CASE WHEN e.cost_usd IS NULL OR e.cost_usd = 0 THEN 1 ELSE 0 END),0)`

	s.mu.Lock()
	defer s.mu.Unlock()

	t := &rep.Total
	if err := s.db.QueryRow(`SELECT `+aggregates+costFrom, sinceStr, untilStr).
		Scan(&t.Calls, &t.Sessions, &t.TokensIn, &t.TokensOut, &t.CostUSD, &t.Unpriced); err != nil {
		log.Printf("store: cost total error: %v", err)
		return rep
	}

	rows, err := s.db.Query(`SELECT `+keyExpr+` AS k, `+aggregates+costFrom+`
		GROUP BY k ORDER BY 6 DESC, 2 DESC, k ASC LIMIT ?`, sinceStr, untilStr, costRowLimit)
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

	if by == "harness" || len(rep.Rows) == 0 {
		return rep
	}
	// Dominant harness per group: most calls wins, ties break alphabetically.
	hrows, err := s.db.Query(`SELECT `+keyExpr+` AS k, s.harness AS h, COUNT(*) AS n`+costFrom+`
		AND s.harness IS NOT NULL AND s.harness != ''
		GROUP BY k, h ORDER BY k, n DESC, h ASC`, sinceStr, untilStr)
	if err != nil {
		log.Printf("store: cost harness error: %v", err)
		return rep
	}
	dominant := map[string]string{}
	for hrows.Next() {
		var k, h string
		var n int
		if err := hrows.Scan(&k, &h, &n); err == nil {
			if _, seen := dominant[k]; !seen {
				dominant[k] = h
			}
		}
	}
	hrows.Close()
	for i := range rep.Rows {
		rep.Rows[i].Harness = dominant[rep.Rows[i].Key]
	}
	return rep
}
