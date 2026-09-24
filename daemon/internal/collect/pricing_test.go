package collect

import (
	"math"
	"testing"
)

// One id per provider family resolves, exact and dated/suffixed; a suffix
// outside the version-boundary rule (a preview tag, not a date) leaves the
// id unpriced rather than absorbed by a shorter family prefix.
func TestBuiltinPricesPerProviderFamily(t *testing.T) {
	cases := []struct {
		id   string
		want [2]float64
		ok   bool
	}{
		{"claude-sonnet-4-5", [2]float64{3, 15}, true},
		{"claude-sonnet-4-5-20250929", [2]float64{3, 15}, true},
		{"gpt-5", [2]float64{1.25, 10}, true},
		{"gpt-5-2025-08-07", [2]float64{1.25, 10}, true},
		{"gpt-5-mini-2025-08-07", [2]float64{0.25, 2}, true},
		{"gpt-4.1-nano-2025-04-14", [2]float64{0.10, 0.40}, true},
		{"o4-mini-2025-04-16", [2]float64{1.10, 4.40}, true},
		{"gemini-2.5-flash", [2]float64{0.30, 2.50}, true},
		{"gemini-2.5-flash-lite-preview-06-17", [2]float64{}, false},
	}
	for _, c := range cases {
		p, ok := lookupPrice(c.id)
		if ok != c.ok || (c.ok && p != c.want) {
			t.Errorf("%s = %v (ok=%v), want %v (ok=%v)", c.id, p, ok, c.want, c.ok)
		}
		if c.ok {
			if got := ModelCostUSD(c.id, 1_000_000, 1_000_000); math.Abs(got-(c.want[0]+c.want[1])) > 1e-9 {
				t.Errorf("%s cost = %v, want %v", c.id, got, c.want[0]+c.want[1])
			}
		}
	}
}

// Provider tables must not share a key: a collision would silently keep one
// provider's price for the other's id.
func TestBuiltinPriceTablesDoNotCollide(t *testing.T) {
	if n := len(anthropicPrices) + len(openAIPrices) + len(googlePrices); len(builtinPrices) != n {
		t.Fatalf("merged table has %d entries, provider tables %d", len(builtinPrices), n)
	}
}

// An id that matches nothing costs 0 — never a fabricated price.
func TestUnknownModelCostsZero(t *testing.T) {
	for _, id := range []string{"some-future-model", "k3-256k", ""} {
		if p, ok := lookupPrice(id); ok {
			t.Errorf("%q resolved to %v, want unpriced", id, p)
		}
		if c := ModelCostUSD(id, 1_000_000, 1_000_000); c != 0 {
			t.Errorf("%q cost = %v, want 0", id, c)
		}
	}
}

// A user entry wins over the built-in table, even when the built-in table
// would also resolve the same id; clearing the table restores the built-in
// price.
func TestUserPricesOverrideBuiltin(t *testing.T) {
	t.Cleanup(func() { SetUserPrices(nil) })
	SetUserPrices(map[string][2]float64{"gpt-5": {2, 20}})
	if p, _ := lookupPrice("gpt-5-latest"); p != [2]float64{2, 20} {
		t.Fatalf("user prefix gpt-5 must win, got %v", p)
	}
	if p, _ := lookupPrice("gpt-4o"); p != [2]float64{2.50, 10} {
		t.Fatalf("ids outside the user table keep the built-in price, got %v", p)
	}
	SetUserPrices(nil)
	if p, _ := lookupPrice("gpt-5-latest"); p != [2]float64{1.25, 10} {
		t.Fatalf("cleared user table must restore the built-in price, got %v", p)
	}
}

// A user prefix prices a dated/suffixed id but not an unrelated variant; an
// exact user entry beats its own prefix.
func TestUserPricePrefixMatchesLongerID(t *testing.T) {
	t.Cleanup(func() { SetUserPrices(nil) })
	SetUserPrices(map[string][2]float64{"k3": {0.60, 2.50}})
	if p, ok := lookupPrice("k3-20260101"); !ok || p != [2]float64{0.60, 2.50} {
		t.Fatalf("k3-20260101 = %v (ok=%v), want the k3 prefix price", p, ok)
	}
	if p, ok := lookupPrice("k3-256k"); ok {
		t.Fatalf("k3-256k = %v, want unpriced (not a date/-latest suffix of k3)", p)
	}
	SetUserPrices(map[string][2]float64{"k3": {0.60, 2.50}, "k3-256k": {1, 4}})
	if p, _ := lookupPrice("k3-256k"); p != [2]float64{1, 4} {
		t.Fatalf("exact entry must beat its prefix, got %v", p)
	}
	if c := ModelCostUSD("k3-256k", 2_000_000, 1_000_000); c != 6 {
		t.Fatalf("cost = %v, want 6", c)
	}
}

// A family prefix absorbs only a date or -latest suffix of the SAME id: a
// different version number or a -pro/-mini/-sol variant is never billed at
// another model's price, built-in or operator-supplied.
func TestVersionBoundaryPrefixRule(t *testing.T) {
	cases := []struct {
		id   string
		want [2]float64
		ok   bool
	}{
		{"claude-opus-5-5", [2]float64{4, 20}, true},
		{"claude-opus-5", [2]float64{5, 25}, true},
		{"claude-opus-4-6", [2]float64{5, 25}, true},
		{"claude-opus-4-20250514", [2]float64{15, 75}, true},
		{"claude-opus-4-1-20250805", [2]float64{15, 75}, true},
		{"claude-fable-5-1", [2]float64{10, 50}, true},
		{"claude-sonnet-5", [2]float64{2, 10}, true},
		{"claude-sonnet-4-5-20250929", [2]float64{3, 15}, true},
		{"claude-haiku-4-5-20251001", [2]float64{1, 5}, true},
		{"gpt-4.1-mini-2025-04-14", [2]float64{0.40, 1.60}, true},
		{"gpt-5-mini", [2]float64{0.25, 2}, true},
		{"o3-pro", [2]float64{}, false},
		{"gpt-5-pro", [2]float64{}, false},
		{"gpt-5.6-sol", [2]float64{}, false},
	}
	for _, c := range cases {
		p, ok := lookupPrice(c.id)
		if ok != c.ok {
			t.Errorf("%s ok=%v, want ok=%v", c.id, ok, c.ok)
			continue
		}
		if c.ok && p != c.want {
			t.Errorf("%s = %v, want %v", c.id, p, c.want)
		}
	}
}

// Classify names why a call is (un)priced: a price entry wins, then a
// subscription or local provider; an empty id is a collection defect.
func TestClassify(t *testing.T) {
	t.Cleanup(func() { SetUserPrices(nil) })
	SetUserPrices(map[string][2]float64{"glm-5.3-flash": {0.1, 0.4}})
	cases := []struct{ model, provider, want string }{
		{"claude-sonnet-4-5", "", ClassPriced},
		{"claude-sonnet-4-5-20250929", "anthropic", ClassPriced},
		{"z-ai/glm-5.3-flash", "openrouter", ClassPriced}, // vendor prefix stripped for the lookup
		{"anthropic/claude-sonnet-4-5", "", ClassPriced},
		{"k3", "kimi-for-coding", ClassPlan},
		{"k3-256k", "kimi-code-plan-global", ClassPlan},
		{"gpt-5.5", "openai-codex", ClassPlan},
		{"llama3.1:8b", "ollama", ClassLocal},
		{"qwen3-coder", "LM-Studio", ClassLocal},
		{"qwen3-coder", "lmstudio", ClassLocal},
		{"gemma", "llama.cpp", ClassLocal},
		{"gemma", "mlx", ClassLocal},
		{"qwen3-coder", "http://127.0.0.1:1234/v1", ClassLocal},
		{"qwen3-coder", "http://localhost:11434", ClassLocal},
		{"", "", ClassUnknownModel},
		{"", "kimi-for-coding", ClassUnknownModel},
		{"gpt-5.6-sol", "custom", ClassUnpricedModel},
		{"codex-auto-review", "openai", ClassUnpricedModel},
		{"z-ai/glm-5.2", "openrouter", ClassUnpricedModel},
	}
	for _, c := range cases {
		if got := Classify(c.model, c.provider); got != c.want {
			t.Errorf("Classify(%q, %q) = %q, want %q", c.model, c.provider, got, c.want)
		}
	}
	// A price entry wins over the plan table: cost and class agree.
	SetUserPrices(map[string][2]float64{"k3": {0.6, 2.5}})
	if got := Classify("k3", "kimi-for-coding"); got != ClassPriced {
		t.Errorf("priced plan model = %q, want priced", got)
	}
}

// The vendor prefix is stripped for the lookup only: the cost resolves, and
// an operator entry keyed by the full id still wins.
func TestVendorPrefixedModelCost(t *testing.T) {
	t.Cleanup(func() { SetUserPrices(nil) })
	if c := ModelCostUSD("anthropic/claude-sonnet-4-5", 1_000_000, 0); math.Abs(c-3) > 1e-9 {
		t.Fatalf("anthropic/claude-sonnet-4-5 cost = %v, want 3", c)
	}
	SetUserPrices(map[string][2]float64{"z-ai/glm-5.3-flash": {1, 1}, "glm-5.3-flash": {2, 2}})
	if c := ModelCostUSD("z-ai/glm-5.3-flash", 1_000_000, 0); math.Abs(c-1) > 1e-9 {
		t.Fatalf("full-id entry cost = %v, want 1", c)
	}
}

// The vendor comes from the built-in table that resolves the id, under the
// same exact/suffix/vendor-prefix rule as the price; the operator table and
// unmatched ids name no vendor.
func TestVendorForModel(t *testing.T) {
	t.Cleanup(func() { SetUserPrices(nil) })
	SetUserPrices(map[string][2]float64{"k3": {1, 1}, "claude-opus-5-5": {9, 9}})
	for model, want := range map[string]string{
		"claude-opus-5-5":            "anthropic",
		"claude-sonnet-4-5-20250929": "anthropic",
		"anthropic/claude-opus-5-5":  "anthropic",
		"gpt-5-mini":                 "openai",
		"gpt-5.6-sol":                "",
		"gemini-2.5-pro":             "google",
		"k3":                         "",
		"":                           "",
	} {
		if got := VendorForModel(model); got != want {
			t.Errorf("VendorForModel(%q) = %q, want %q", model, got, want)
		}
	}
}
