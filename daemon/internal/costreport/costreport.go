// Package costreport classifies the zero-cost model calls of a cost report by
// price class and reads cost window lookbacks.
package costreport

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// UnpricedRow is one (harness, provider, model) whose calls carry no
// cost, with the reason.
type UnpricedRow struct {
	Harness   string `json:"harness"`
	Provider  string `json:"provider"`
	Model     string `json:"model"`
	Class     string `json:"class"`
	Calls     int    `json:"calls"`
	TokensIn  int64  `json:"tokens_in"`
	TokensOut int64  `json:"tokens_out"`
}

// UnpricedReport is the /costs/unpriced body.
type UnpricedReport struct {
	Since string        `json:"since"`
	Until string        `json:"until"`
	Rows  []UnpricedRow `json:"rows"`
}

// Unpriced keeps the groups of rep whose calls are not priced.
func Unpriced(rep store.CostReport) UnpricedReport {
	out := UnpricedReport{Since: rep.Since, Until: rep.Until, Rows: []UnpricedRow{}}
	for _, g := range rep.Groups {
		class := collect.Classify(g.Model, g.Provider)
		if class == collect.ClassPriced {
			continue
		}
		out.Rows = append(out.Rows, UnpricedRow{
			Harness: g.Key, Provider: g.Provider, Model: g.Model, Class: class,
			Calls: g.Calls, TokensIn: g.TokensIn, TokensOut: g.TokensOut,
		})
	}
	return out
}

// Classify splits each row's and the total's zero-cost calls by price
// class, names the class of each by=model row (priced when every call
// carries a cost, else the model's class under its dominant provider), then
// narrows unpriced_calls to the unknown-model and unpriced-model calls.
func Classify(rep *store.CostReport) {
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

// ParseSince accepts a lookback ("24h", "90m", "7d") or an RFC3339
// timestamp. Shared by /costs and /sessions.
func ParseSince(v string, now time.Time) (time.Time, error) {
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
