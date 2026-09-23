package main

import (
	"strings"
	"testing"
)

func TestFormatCostTable(t *testing.T) {
	rep := costReport{
		By: "repo",
		Rows: []costRow{
			{Key: "api-service", Harness: "claude", Calls: 12, Sessions: 2, TokensIn: 45000, TokensOut: 3200, CostUSD: 1234.5, Unpriced: 1},
			{Key: "scratch", Harness: "opencode", Calls: 1, Sessions: 1, TokensIn: 10, TokensOut: 2, CostUSD: 0.004},
		},
		Total: costRow{Calls: 13, Sessions: 3, TokensIn: 45010, TokensOut: 3202, CostUSD: 1234.504, Unpriced: 1},
	}
	out := formatCostTable(rep)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("want header + 2 rows + total, got %d lines:\n%s", len(lines), out)
	}
	for _, col := range []string{"KEY", "HARNESS", "CALLS", "SESSIONS", "TOKENS IN", "TOKENS OUT", "COST", "UNPRICED"} {
		if !strings.Contains(lines[0], col) {
			t.Fatalf("header missing %q: %q", col, lines[0])
		}
	}
	if f := strings.Fields(lines[1]); len(f) != 8 || f[0] != "api-service" || f[1] != "claude" || f[2] != "12" || f[6] != "$1,234.50" || f[7] != "1" {
		t.Fatalf("row = %q", lines[1])
	}
	if !strings.Contains(lines[2], "<$0.01") {
		t.Fatalf("sub-cent row must read <$0.01: %q", lines[2])
	}
	if f := strings.Fields(lines[3]); f[0] != "TOTAL" || f[1] != "13" || f[5] != "$1,234.50" {
		t.Fatalf("total line = %q", lines[3])
	}
	width := len([]rune(lines[0]))
	for i, l := range lines {
		if len([]rune(l)) != width {
			t.Fatalf("line %d width %d, header %d — columns not fixed-width:\n%s", i, len([]rune(l)), width, out)
		}
	}
}

func TestFmtUSDCLI(t *testing.T) {
	for in, want := range map[float64]string{0: "$0.00", 0.004: "<$0.01", 36.674: "$36.67", 1234.5: "$1,234.50", 1234567: "$1,234,567.00"} {
		if got := fmtUSD(in); got != want {
			t.Errorf("fmtUSD(%v) = %q, want %q", in, got, want)
		}
	}
}
