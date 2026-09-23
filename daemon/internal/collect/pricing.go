package collect

import (
	"strings"
	"sync/atomic"
)

// Model price tables, USD per 1M tokens as [input, output], one map per
// provider family. Keys are matched by PREFIX so a dated or suffixed id
// ("claude-sonnet-4-5-20250929", "gpt-4.1-mini-2025-04-14") resolves to its
// family price without a per-date table; the longest matching prefix wins.
// Cost is approximate by design: cache-read discounts and tier pricing are
// not modeled. An id that matches no entry costs 0 and is counted as
// unpriced — never a fabricated number.

// anthropicPrices holds Anthropic list prices.
var anthropicPrices = map[string][2]float64{
	"claude-fable":      {3, 15},
	"claude-opus-5":     {5, 25},
	"claude-opus-4":     {15, 75},
	"claude-sonnet-5":   {3, 15},
	"claude-sonnet-4":   {3, 15},
	"claude-haiku-4-5":  {1, 5},
	"claude-haiku-4":    {1, 5},
	"claude-haiku-3-5":  {0.80, 4},
	"claude-3-5-sonnet": {3, 15},
	"claude-3-opus":     {15, 75},
	"claude-3-haiku":    {0.25, 1.25},
}

// openAIPrices holds OpenAI list prices.
var openAIPrices = map[string][2]float64{
	"gpt-5":        {1.25, 10},
	"gpt-5-mini":   {0.25, 2},
	"gpt-5-nano":   {0.05, 0.40},
	"gpt-4.1":      {2, 8},
	"gpt-4.1-mini": {0.40, 1.60},
	"gpt-4.1-nano": {0.10, 0.40},
	"gpt-4o":       {2.50, 10},
	"gpt-4o-mini":  {0.15, 0.60},
	"o3":           {2, 8},
	"o4-mini":      {1.10, 4.40},
}

// googlePrices holds Google Gemini list prices.
var googlePrices = map[string][2]float64{
	"gemini-2.5-pro":        {1.25, 10},
	"gemini-2.5-flash":      {0.30, 2.50},
	"gemini-2.5-flash-lite": {0.10, 0.40},
}

// builtinPrices is every provider table in one lookup map.
var builtinPrices = mergePrices(anthropicPrices, openAIPrices, googlePrices)

func mergePrices(tables ...map[string][2]float64) map[string][2]float64 {
	out := map[string][2]float64{}
	for _, t := range tables {
		for id, p := range t {
			out[id] = p
		}
	}
	return out
}

// userPrices is the operator's table from config.yaml (`pricing`). It is
// replaced whole, so a lookup never sees a half-applied reload, and it is
// consulted before the built-in table.
var userPrices atomic.Pointer[map[string][2]float64]

// SetUserPrices replaces the operator price table (USD per 1M tokens,
// [input, output]). Entries follow the built-in lookup rule — exact id, then
// longest prefix — and win over the built-in table. nil clears it.
func SetUserPrices(prices map[string][2]float64) {
	table := make(map[string][2]float64, len(prices))
	for id, p := range prices {
		table[id] = p
	}
	userPrices.Store(&table)
}

// ModelCostUSD approximates one call's cost. Cache-read tokens are billed as
// input here (the approximation is documented); unknown models return 0.
func ModelCostUSD(model string, in, out int64) float64 {
	price, ok := lookupPrice(model)
	if !ok {
		return 0
	}
	return (float64(in)*price[0] + float64(out)*price[1]) / 1e6
}

// lookupPrice resolves a model id against the operator table first, then the
// built-in table.
func lookupPrice(model string) ([2]float64, bool) {
	if model == "" {
		return [2]float64{}, false
	}
	if user := userPrices.Load(); user != nil {
		if p, ok := matchPrice(*user, model); ok {
			return p, true
		}
	}
	return matchPrice(builtinPrices, model)
}

// matchPrice resolves a model id by exact match first, then the longest
// matching prefix (so dated ids and minor suffixes work).
func matchPrice(table map[string][2]float64, model string) ([2]float64, bool) {
	if p, ok := table[model]; ok {
		return p, true
	}
	best := ""
	for prefix := range table {
		if strings.HasPrefix(model, prefix) && len(prefix) > len(best) {
			best = prefix
		}
	}
	if best == "" {
		return [2]float64{}, false
	}
	return table[best], true
}
