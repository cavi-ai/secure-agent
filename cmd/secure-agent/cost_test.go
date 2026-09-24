package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
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

// fakeDaemon serves canned /costs and /costs/unpriced bodies; the client
// dials it for the CLI's http://unix/ URLs.
func fakeDaemon(t *testing.T, costs, unpriced string) *http.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/costs":
			fmt.Fprint(w, costs)
		case "/costs/unpriced":
			fmt.Fprint(w, unpriced)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}}}
}

const costsWithClasses = `{"since":"2026-09-22T06:30:00Z","until":"2026-09-23T06:30:00Z","by":"repo",` +
	`"total":{"key":"","calls":8,"sessions":3,"tokens_in":800,"tokens_out":80,"cost_usd":0.5,"unpriced_calls":4,` +
	`"unknown_model_calls":1,"unpriced_model_calls":3,"plan_calls":2,"local_calls":1},` +
	`"rows":[{"key":"A","harness":"codex","calls":8,"sessions":3,"tokens_in":800,"tokens_out":80,"cost_usd":0.5,"unpriced_calls":4,` +
	`"unknown_model_calls":1,"unpriced_model_calls":3,"plan_calls":2,"local_calls":1}]}`

const unpricedRows = `{"since":"2026-09-22T06:30:00Z","until":"2026-09-23T06:30:00Z","rows":[` +
	`{"harness":"codex","provider":"custom","model":"gpt-5.6-sol","class":"unpriced-model","calls":2,"tokens_in":200,"tokens_out":20},` +
	`{"harness":"opencode","provider":"kimi-for-coding","model":"k3","class":"plan","calls":2,"tokens_in":200,"tokens_out":20},` +
	`{"harness":"opencode","provider":"openrouter","model":"gpt-5.6-sol","class":"unpriced-model","calls":1,"tokens_in":100,"tokens_out":10},` +
	`{"harness":"codex","provider":"","model":"","class":"unknown-model","calls":1,"tokens_in":100,"tokens_out":10},` +
	`{"harness":"opencode","provider":"ollama","model":"llama3.1:8b","class":"local","calls":1,"tokens_in":100,"tokens_out":10}]}`

// --json passes the class counters through; the table view prints the class
// breakdown and one pricing hint per unpriced model id.
func TestRunCostClassesAndHints(t *testing.T) {
	client := fakeDaemon(t, costsWithClasses, unpricedRows)

	var js strings.Builder
	if err := runCost(&js, client, []string{"--since", "24h", "--json"}); err != nil {
		t.Fatal(err)
	}
	var rep costReport
	if err := json.Unmarshal([]byte(js.String()), &rep); err != nil {
		t.Fatalf("--json output is not the /costs body: %v", err)
	}
	if tot := rep.Total; tot.UnknownModel != 1 || tot.UnpricedModel != 3 || tot.Plan != 2 || tot.Local != 1 || tot.Unpriced != 4 {
		t.Fatalf("--json total = %+v", tot)
	}

	var out strings.Builder
	if err := runCost(&out, client, []string{"--since", "24h"}); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"plan: 2 · local: 1 · unpriced: 4 — 1 unknown model, 3 unpriced model",
		"add a price for gpt-5.6-sol under pricing: in ~/.config/secure-agent/config.yaml",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("output missing %q:\n%s", want, text)
		}
	}
	if c := strings.Count(text, "add a price for"); c != 1 {
		t.Fatalf("want one hint per unpriced model id, got %d:\n%s", c, text)
	}

	// Plan calls only: the split line prints, no hints.
	var planOnly strings.Builder
	onPlans := strings.NewReplacer(`"unpriced_calls":4`, `"unpriced_calls":0`, `"local_calls":1`, `"local_calls":0`,
		`"unknown_model_calls":1`, `"unknown_model_calls":0`, `"unpriced_model_calls":3`, `"unpriced_model_calls":0`).Replace(costsWithClasses)
	if err := runCost(&planOnly, fakeDaemon(t, onPlans, unpricedRows), nil); err != nil {
		t.Fatal(err)
	}
	if text := planOnly.String(); !strings.Contains(text, "plan: 2 · local: 0 · unpriced: 0 — 0 unknown model, 0 unpriced model") ||
		strings.Contains(text, "add a price for") {
		t.Fatalf("plan-only split:\n%s", text)
	}

	// Nothing on plans, local or unpriced: no split line, no hints.
	var clean strings.Builder
	allPriced := strings.NewReplacer(`"plan_calls":2`, `"plan_calls":0`).Replace(onPlans)
	if err := runCost(&clean, fakeDaemon(t, allPriced, `{"rows":[]}`), nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(clean.String(), "unpriced:") {
		t.Fatalf("split printed with every call priced:\n%s", clean.String())
	}
}

// --by day --tz -240 reach /costs as by=day&tz=-240; --tz defaults to this
// machine's offset; day rows print oldest first.
func TestRunCostByDayPassesTZ(t *testing.T) {
	var got []url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/costs" {
			got = append(got, r.URL.Query())
		}
		fmt.Fprint(w, `{"by":"day","total":{"calls":3,"cost_usd":3},"rows":[`+
			`{"key":"2026-09-23","calls":1,"cost_usd":1},{"key":"2026-09-21","calls":1,"cost_usd":1},{"key":"2026-09-22","calls":1,"cost_usd":1}]}`)
	}))
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}}}

	var out strings.Builder
	if err := runCost(&out, client, []string{"--since", "7d", "--by", "day", "--tz", "-240"}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Get("by") != "day" || got[0].Get("tz") != "-240" || got[0].Get("since") != "7d" {
		t.Fatalf("/costs query = %v, want since=7d by=day tz=-240", got)
	}
	text := out.String()
	a, b, c := strings.Index(text, "2026-09-21"), strings.Index(text, "2026-09-22"), strings.Index(text, "2026-09-23")
	if a < 0 || !(a < b && b < c) {
		t.Fatalf("day rows not oldest first:\n%s", text)
	}

	if err := runCost(io.Discard, client, []string{"--by", "day"}); err != nil {
		t.Fatal(err)
	}
	_, offset := time.Now().Zone()
	if tz := got[1].Get("tz"); tz != strconv.Itoa(offset/60) {
		t.Fatalf("default tz = %q, want this machine's offset %d", tz, offset/60)
	}
}
