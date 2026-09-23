package collect

import (
	"math"
	"testing"
)

// One id per provider family resolves, exact and dated/suffixed; the
// longest prefix wins over a shorter family prefix.
func TestBuiltinPricesPerProviderFamily(t *testing.T) {
	cases := []struct {
		id   string
		want [2]float64
	}{
		{"claude-sonnet-4-5", [2]float64{3, 15}},
		{"claude-sonnet-4-5-20250929", [2]float64{3, 15}},
		{"gpt-5", [2]float64{1.25, 10}},
		{"gpt-5-2025-08-07", [2]float64{1.25, 10}},
		{"gpt-5-mini-2025-08-07", [2]float64{0.25, 2}},
		{"gpt-4.1-nano-2025-04-14", [2]float64{0.10, 0.40}},
		{"o4-mini-2025-04-16", [2]float64{1.10, 4.40}},
		{"gemini-2.5-flash", [2]float64{0.30, 2.50}},
		{"gemini-2.5-flash-lite-preview-06-17", [2]float64{0.10, 0.40}},
	}
	for _, c := range cases {
		p, ok := lookupPrice(c.id)
		if !ok || p != c.want {
			t.Errorf("%s = %v (ok=%v), want %v", c.id, p, ok, c.want)
		}
		if got := ModelCostUSD(c.id, 1_000_000, 1_000_000); math.Abs(got-(c.want[0]+c.want[1])) > 1e-9 {
			t.Errorf("%s cost = %v, want %v", c.id, got, c.want[0]+c.want[1])
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

// A user entry wins over the built-in table, even over a longer built-in
// prefix; clearing the table restores the built-in price.
func TestUserPricesOverrideBuiltin(t *testing.T) {
	t.Cleanup(func() { SetUserPrices(nil) })
	SetUserPrices(map[string][2]float64{"gpt-5": {2, 20}})
	if p, _ := lookupPrice("gpt-5-mini-2025-08-07"); p != [2]float64{2, 20} {
		t.Fatalf("user prefix gpt-5 must win, got %v", p)
	}
	if p, _ := lookupPrice("gpt-4o"); p != [2]float64{2.50, 10} {
		t.Fatalf("ids outside the user table keep the built-in price, got %v", p)
	}
	SetUserPrices(nil)
	if p, _ := lookupPrice("gpt-5-mini-2025-08-07"); p != [2]float64{0.25, 2} {
		t.Fatalf("cleared user table must restore the built-in price, got %v", p)
	}
}

// A user prefix prices a longer id; an exact user entry beats its prefix.
func TestUserPricePrefixMatchesLongerID(t *testing.T) {
	t.Cleanup(func() { SetUserPrices(nil) })
	SetUserPrices(map[string][2]float64{"k3": {0.60, 2.50}})
	if p, ok := lookupPrice("k3-256k"); !ok || p != [2]float64{0.60, 2.50} {
		t.Fatalf("k3-256k = %v (ok=%v), want the k3 prefix price", p, ok)
	}
	SetUserPrices(map[string][2]float64{"k3": {0.60, 2.50}, "k3-256k": {1, 4}})
	if p, _ := lookupPrice("k3-256k"); p != [2]float64{1, 4} {
		t.Fatalf("exact entry must beat its prefix, got %v", p)
	}
	if c := ModelCostUSD("k3-256k", 2_000_000, 1_000_000); c != 6 {
		t.Fatalf("cost = %v, want 6", c)
	}
}
