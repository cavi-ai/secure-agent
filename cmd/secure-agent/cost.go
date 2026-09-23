package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
)

// costRow and costReport mirror the daemon's GET /costs body.
type costRow struct {
	Key       string  `json:"key"`
	Harness   string  `json:"harness,omitempty"`
	Calls     int     `json:"calls"`
	Sessions  int     `json:"sessions"`
	TokensIn  int64   `json:"tokens_in"`
	TokensOut int64   `json:"tokens_out"`
	CostUSD   float64 `json:"cost_usd"`
	Unpriced  int     `json:"unpriced_calls"`
}

type costReport struct {
	Since string    `json:"since"`
	Until string    `json:"until"`
	By    string    `json:"by"`
	Total costRow   `json:"total"`
	Rows  []costRow `json:"rows"`
}

func handleCost(client *http.Client) {
	args := os.Args[2:]
	q := url.Values{}
	q.Set("since", queryFlag(args, "--since", "24h"))
	q.Set("by", queryFlag(args, "--by", "repo"))
	code, body := request(client, http.MethodGet, "http://unix/costs?"+q.Encode(), "")
	if code != 200 {
		fmt.Printf("cost failed (%d): %s\n", code, strings.TrimSpace(body))
		os.Exit(1)
	}
	if slices.Contains(args, "--json") {
		fmt.Println(body)
		return
	}
	var rep costReport
	if err := json.Unmarshal([]byte(body), &rep); err != nil {
		fmt.Printf("cost: unreadable response: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(formatCostTable(rep))
}

const costKeyMaxWidth = 48

// formatCostTable renders a CostReport as a fixed-width table with a TOTAL
// line.
func formatCostTable(rep costReport) string {
	keyW, harnessW := len("TOTAL"), len("HARNESS")
	for _, r := range rep.Rows {
		keyW = max(keyW, len([]rune(r.Key)))
		harnessW = max(harnessW, len([]rune(r.Harness)))
	}
	keyW = min(keyW, costKeyMaxWidth)

	var b strings.Builder
	fmt.Fprintf(&b, "%-*s  %-*s  %6s  %8s  %10s  %10s  %11s  %8s\n",
		keyW, "KEY", harnessW, "HARNESS", "CALLS", "SESSIONS", "TOKENS IN", "TOKENS OUT", "COST", "UNPRICED")
	line := func(key, harness string, r costRow) {
		fmt.Fprintf(&b, "%-*s  %-*s  %6d  %8d  %10d  %10d  %11s  %8d\n",
			keyW, clipRunes(key, keyW), harnessW, harness, r.Calls, r.Sessions, r.TokensIn, r.TokensOut, fmtUSD(r.CostUSD), r.Unpriced)
	}
	for _, r := range rep.Rows {
		line(r.Key, r.Harness, r)
	}
	line("TOTAL", "", rep.Total)
	return b.String()
}

// fmtUSD renders dollars with two decimals and thousands separators; a
// non-zero amount under a cent reads "<$0.01" rather than "$0.00".
func fmtUSD(v float64) string {
	if v > 0 && v < 0.01 {
		return "<$0.01"
	}
	s := strconv.FormatFloat(v, 'f', 2, 64)
	whole, frac, _ := strings.Cut(s, ".")
	var g strings.Builder
	for i, c := range whole {
		if i > 0 && (len(whole)-i)%3 == 0 {
			g.WriteByte(',')
		}
		g.WriteRune(c)
	}
	return "$" + g.String() + "." + frac
}

func clipRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
