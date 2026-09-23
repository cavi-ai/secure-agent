package collect

import (
	"regexp"
	"strings"
	"sync/atomic"
)

// Model price tables, USD per 1M tokens as [input, output], one map per
// provider family. Keys are matched by exact id first, then by the longest
// prefix P such that model[len(P):] is empty, "-latest", a date suffix
// ("-20250929", "-2025-09-29"), or "@20250929" — a family entry only
// absorbs a date or -latest suffix of the SAME id, never a different
// version or a -pro/-mini/-sol variant. Cost is approximate by design:
// cache-read discounts and tier pricing are not modeled. An id that matches
// no entry costs 0 and is counted as unpriced — never a fabricated number.

// anthropicPrices holds Anthropic list prices.
var anthropicPrices = map[string][2]float64{
	"claude-fable-5-1":  {10, 50},
	"claude-fable-5":    {10, 50},
	"claude-mythos-5-1": {10, 50},
	"claude-mythos-5":   {10, 50},
	"claude-opus-5-5":   {4, 20},
	"claude-opus-5":     {5, 25},
	"claude-opus-4-8":   {5, 25},
	"claude-opus-4-7":   {5, 25},
	"claude-opus-4-6":   {5, 25},
	"claude-opus-4-5":   {5, 25},
	"claude-opus-4-1":   {15, 75},
	"claude-opus-4-0":   {15, 75},
	"claude-opus-4":     {15, 75},
	"claude-sonnet-5":   {2, 10},
	"claude-sonnet-4-6": {3, 15},
	"claude-sonnet-4-5": {3, 15},
	"claude-sonnet-4-0": {3, 15},
	"claude-sonnet-4":   {3, 15},
	"claude-haiku-4-5":  {1, 5},
	"claude-3-7-sonnet": {3, 15},
	"claude-3-5-sonnet": {3, 15},
	"claude-3-5-haiku":  {0.80, 4},
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
// built-in table. A vendor-prefixed id ("z-ai/glm-5.3-flash") that matches
// nothing as written is looked up again without its prefix.
func lookupPrice(model string) ([2]float64, bool) {
	return resolveModelID(model, lookupPriceExact)
}

// resolveModelID applies match to model as written, then, for a
// vendor-prefixed id, to the part after its last '/'.
func resolveModelID[T any](model string, match func(string) (T, bool)) (T, bool) {
	var zero T
	if model == "" {
		return zero, false
	}
	if v, ok := match(model); ok {
		return v, true
	}
	if i := strings.LastIndexByte(model, '/'); i >= 0 && i+1 < len(model) {
		return match(model[i+1:])
	}
	return zero, false
}

// builtinVendor names the vendor table each built-in price entry comes from.
var builtinVendor = vendorOf(map[string]map[string][2]float64{
	"anthropic": anthropicPrices,
	"openai":    openAIPrices,
	"google":    googlePrices,
})

func vendorOf(tables map[string]map[string][2]float64) map[string]string {
	out := map[string]string{}
	for vendor, t := range tables {
		for id := range t {
			out[id] = vendor
		}
	}
	return out
}

// VendorForModel names the vendor whose built-in price table resolves model
// under the lookup rule ("anthropic", "openai" or "google"), or "" when no
// built-in entry matches. The operator table names no vendor, so it is not
// consulted.
func VendorForModel(model string) string {
	vendor, _ := resolveModelID(model, func(id string) (string, bool) {
		key, ok := matchPriceKey(builtinPrices, id)
		return builtinVendor[key], ok
	})
	return vendor
}

func lookupPriceExact(model string) ([2]float64, bool) {
	if user := userPrices.Load(); user != nil {
		if p, ok := matchPrice(*user, model); ok {
			return p, true
		}
	}
	return matchPrice(builtinPrices, model)
}

// Price classes: why a model call does or does not carry a cost.
const (
	ClassPriced        = "priced"         // a price entry resolves the model id
	ClassPlan          = "plan"           // a subscription provider: no per-call price exists
	ClassLocal         = "local"          // a local runtime: no per-call price exists
	ClassUnknownModel  = "unknown-model"  // the harness recorded no model id
	ClassUnpricedModel = "unpriced-model" // the id is known, no entry prices it: add one under `pricing`
)

// planProviders are subscription plans billed per seat, not per token, as the
// harness names the provider (opencode providerID).
var planProviders = map[string]bool{
	"kimi-for-coding":       true,
	"kimi-code-plan-global": true,
}

// localProviders are local model runtimes.
var localProviders = map[string]bool{
	"ollama":    true,
	"lmstudio":  true,
	"lm-studio": true,
	"llama.cpp": true,
	"mlx":       true,
}

// Classify names a model call's price class. An empty id is unknown-model
// whatever the provider (the harness failed to name it); a price entry wins
// over the provider tables, so class and ModelCostUSD agree.
func Classify(model, provider string) string {
	if model == "" {
		return ClassUnknownModel
	}
	if _, ok := lookupPrice(model); ok {
		return ClassPriced
	}
	p := strings.ToLower(provider)
	switch {
	case planProviders[p]:
		return ClassPlan
	case localProviders[p], strings.Contains(p, "localhost"), strings.Contains(p, "127.0.0.1"), strings.Contains(p, "[::1]"):
		return ClassLocal
	}
	return ClassUnpricedModel
}

// versionSuffixRE is the only remainder a prefix may absorb past an exact
// match: a `-latest` tag, a `YYYYMMDD` or `YYYY-MM-DD` date, or an
// `@YYYYMMDD` snapshot tag. A remainder outside this set — another version
// number, `-pro`, `-mini`, `-sol` — means the prefix names a different
// model, not a suffix of this one.
var versionSuffixRE = regexp.MustCompile(`^(-latest|-\d{8}|-\d{4}-\d{2}-\d{2}|@\d{8})$`)

// matchPrice resolves a model id by exact match first, then the longest
// prefix P in table where model[len(P):] matches versionSuffixRE.
func matchPrice(table map[string][2]float64, model string) ([2]float64, bool) {
	key, ok := matchPriceKey(table, model)
	return table[key], ok
}

// matchPriceKey returns the entry of table that resolves model under the
// matchPrice rule.
func matchPriceKey(table map[string][2]float64, model string) (string, bool) {
	if _, ok := table[model]; ok {
		return model, true
	}
	best := ""
	for prefix := range table {
		if len(prefix) <= len(best) {
			continue
		}
		if !strings.HasPrefix(model, prefix) {
			continue
		}
		if versionSuffixRE.MatchString(model[len(prefix):]) {
			best = prefix
		}
	}
	return best, best != ""
}
