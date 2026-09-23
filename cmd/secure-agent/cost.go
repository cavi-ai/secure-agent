package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// costRow and costReport mirror the daemon's GET /costs body.
type costRow struct {
	Key           string  `json:"key"`
	Harness       string  `json:"harness,omitempty"`
	Provider      string  `json:"provider,omitempty"`
	Class         string  `json:"class,omitempty"`
	Calls         int     `json:"calls"`
	Sessions      int     `json:"sessions"`
	TokensIn      int64   `json:"tokens_in"`
	TokensOut     int64   `json:"tokens_out"`
	CostUSD       float64 `json:"cost_usd"`
	Unpriced      int     `json:"unpriced_calls"`
	UnknownModel  int     `json:"unknown_model_calls"`
	UnpricedModel int     `json:"unpriced_model_calls"`
	Plan          int     `json:"plan_calls"`
	Local         int     `json:"local_calls"`
}

type costReport struct {
	Since string    `json:"since"`
	Until string    `json:"until"`
	By    string    `json:"by"`
	Total costRow   `json:"total"`
	Rows  []costRow `json:"rows"`
}

// unpricedRow mirrors one row of the daemon's GET /costs/unpriced body.
type unpricedRow struct {
	Harness  string `json:"harness"`
	Provider string `json:"provider"`
	Model    string `json:"model"`
	Class    string `json:"class"`
	Calls    int    `json:"calls"`
}

func handleCost(client *http.Client) {
	if err := runCost(os.Stdout, client, os.Args[2:]); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// runCost prints GET /costs as a table (or the raw body with --json), then,
// when calls are unpriced, their class breakdown and a pricing hint per
// unpriced model id from GET /costs/unpriced. --tz (minutes east of UTC)
// defaults to this machine's current offset.
func runCost(w io.Writer, client *http.Client, args []string) error {
	since := queryFlag(args, "--since", "24h")
	_, offset := time.Now().Zone()
	q := url.Values{}
	q.Set("since", since)
	q.Set("by", queryFlag(args, "--by", "repo"))
	q.Set("tz", queryFlag(args, "--tz", strconv.Itoa(offset/60)))
	code, body := request(client, http.MethodGet, "http://unix/costs?"+q.Encode(), "")
	if code != 200 {
		return fmt.Errorf("cost failed (%d): %s", code, strings.TrimSpace(body))
	}
	if slices.Contains(args, "--json") {
		fmt.Fprintln(w, body)
		return nil
	}
	var rep costReport
	if err := json.Unmarshal([]byte(body), &rep); err != nil {
		return fmt.Errorf("cost: unreadable response: %v", err)
	}
	fmt.Fprint(w, formatCostTable(rep))
	if rep.Total.Unpriced == 0 {
		return nil
	}
	// An older daemon has no /costs/unpriced: the breakdown prints without hints.
	var unpriced struct {
		Rows []unpricedRow `json:"rows"`
	}
	if code, body := request(client, http.MethodGet, "http://unix/costs/unpriced?"+url.Values{"since": {since}}.Encode(), ""); code == 200 {
		_ = json.Unmarshal([]byte(body), &unpriced)
	}
	fmt.Fprint(w, formatCostClasses(rep.Total, unpriced.Rows))
	return nil
}

// formatCostClasses renders why calls are unpriced and one hint per model id
// that only needs a price entry.
func formatCostClasses(total costRow, rows []unpricedRow) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\nunpriced: %d calls — %d unknown model, %d unpriced model, %d plan, %d local\n",
		total.Unpriced, total.UnknownModel, total.UnpricedModel, total.Plan, total.Local)
	seen := map[string]bool{}
	for _, r := range rows {
		if r.Class != "unpriced-model" || seen[r.Model] {
			continue
		}
		seen[r.Model] = true
		fmt.Fprintf(&b, "add a price for %s under pricing: in ~/.config/secure-agent/config.yaml\n", r.Model)
	}
	return b.String()
}

const costKeyMaxWidth = 48

// formatCostTable renders a CostReport as a fixed-width table with a TOTAL
// line; by=day rows print oldest first.
func formatCostTable(rep costReport) string {
	if rep.By == "day" {
		rep.Rows = slices.Clone(rep.Rows)
		slices.SortStableFunc(rep.Rows, func(a, b costRow) int { return strings.Compare(a.Key, b.Key) })
	}
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
