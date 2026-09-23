package store

import (
	"encoding/json"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func seedCostStore(t *testing.T, now time.Time) *Store {
	t.Helper()
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	for _, sess := range []model.Session{
		{ID: "s1", Harness: "claude", Repo: "A", Branch: "main"},
		{ID: "s2", Harness: "opencode", Repo: "B"},
		{ID: "s3", Harness: "codex"},
	} {
		sess.StartedAt, sess.LastSeenAt, sess.Status = now, now, model.SessionActive
		s.UpsertSession(sess)
	}
	call := func(sid, mdl string, cost float64, ago time.Duration) {
		s.PutEvent(event.Event{
			Kind: event.KindModelCall, TS: now.Add(-ago), SessionID: sid,
			Model: mdl, TokensIn: 100, TokensOut: 10, CostUSD: cost,
		})
	}
	call("s1", "m1", 0.5, time.Hour)
	call("s1", "m1", 0.25, 2*time.Hour)
	call("s2", "m2", 0.1, time.Hour)
	call("s3", "", 0, time.Hour)
	call("s1", "m1", 9, 48*time.Hour) // outside the 24h window
	return s
}

func costRowsByKey(rows []CostRow) map[string]CostRow {
	out := map[string]CostRow{}
	for _, r := range rows {
		out[r.Key] = r
	}
	return out
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestCostReportByRepo(t *testing.T) {
	now := time.Now()
	s := seedCostStore(t, now)
	rep := s.CostReport(now.Add(-24*time.Hour), now, "repo", CostOptions{})

	if rep.By != "repo" || len(rep.Rows) != 3 {
		t.Fatalf("by=%q rows=%+v, want 3 repo rows", rep.By, rep.Rows)
	}
	if rep.Rows[0].Key != "A" || rep.Rows[1].Key != "B" || rep.Rows[2].Key != "(no repo)" {
		t.Fatalf("rows not sorted by cost desc: %+v", rep.Rows)
	}
	got := costRowsByKey(rep.Rows)
	if a := got["A"]; !near(a.CostUSD, 0.75) || a.Calls != 2 || a.Sessions != 1 || a.Harness != "claude" || a.TokensIn != 200 || a.TokensOut != 20 {
		t.Fatalf("repo A = %+v, want 0.75 over 2 calls from claude", a)
	}
	if b := got["B"]; !near(b.CostUSD, 0.1) || b.Calls != 1 || b.Harness != "opencode" {
		t.Fatalf("repo B = %+v, want 0.1 over 1 call", b)
	}
	if n := got["(no repo)"]; n.CostUSD != 0 || n.Unpriced != 1 || n.Calls != 1 {
		t.Fatalf("(no repo) = %+v, want 0 cost, 1 unpriced", n)
	}
	tot := rep.Total
	if !near(tot.CostUSD, 0.85) || tot.Calls != 4 || tot.Unpriced != 1 || tot.Sessions != 3 || tot.Key != "" {
		t.Fatalf("total = %+v, want 0.85 / 4 calls / 1 unpriced / 3 sessions (48h-old call excluded)", tot)
	}
}

func TestCostReportByModelSessionAndUnknownGroup(t *testing.T) {
	now := time.Now()
	s := seedCostStore(t, now)
	since := now.Add(-24 * time.Hour)

	byModel := costRowsByKey(s.CostReport(since, now, "model", CostOptions{}).Rows)
	if len(byModel) != 3 || !near(byModel["m1"].CostUSD, 0.75) || !near(byModel["m2"].CostUSD, 0.1) ||
		byModel["(unknown)"].Unpriced != 1 || byModel["(unknown)"].CostUSD != 0 {
		t.Fatalf("by=model rows = %+v", byModel)
	}

	bySession := costRowsByKey(s.CostReport(since, now, "session", CostOptions{}).Rows)
	if len(bySession) != 3 || bySession["s1"].Calls != 2 || bySession["s2"].Calls != 1 || bySession["s3"].Calls != 1 {
		t.Fatalf("by=session rows = %+v, want s1/s2/s3", bySession)
	}
	if bySession["s3"].Harness != "codex" {
		t.Fatalf("session s3 harness = %q, want codex", bySession["s3"].Harness)
	}

	fallback := s.CostReport(since, now, "nope", CostOptions{})
	if fallback.By != "repo" || len(fallback.Rows) != 3 || fallback.Rows[0].Key != "A" {
		t.Fatalf("unknown by must behave as repo: %+v", fallback)
	}

	byBranch := costRowsByKey(s.CostReport(since, now, "branch", CostOptions{}).Rows)
	if _, ok := byBranch["A@main"]; !ok {
		t.Fatalf("by=branch rows = %+v, want A@main", byBranch)
	}
}

func TestCostReportEmptyStoreRowsNeverNull(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	rep := s.CostReport(now.Add(-24*time.Hour), now, "repo", CostOptions{})
	if rep.Rows == nil {
		t.Fatal("Rows is nil on an empty store; must be []")
	}
	b, _ := json.Marshal(rep)
	if !strings.Contains(string(b), `"rows":[]`) {
		t.Fatalf("empty report JSON = %s, want rows: []", b)
	}
}

// The provider round-trips through the store; by=model rows carry the
// model's dominant provider; Groups break the zero-cost calls down by
// (group, model, provider) for classification, excluding priced calls.
func TestCostReportProviderAndUnpricedGroups(t *testing.T) {
	now := time.Now()
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	for _, sess := range []model.Session{{ID: "oc", Harness: "opencode"}, {ID: "cx", Harness: "codex"}} {
		sess.StartedAt, sess.LastSeenAt, sess.Status = now, now, model.SessionActive
		s.UpsertSession(sess)
	}
	call := func(sid, mdl, provider string, cost float64, ago time.Duration) {
		s.PutEvent(event.Event{Kind: event.KindModelCall, TS: now.Add(-ago), SessionID: sid,
			Model: mdl, Provider: provider, TokensIn: 100, TokensOut: 10, CostUSD: cost})
	}
	call("oc", "k3", "kimi-for-coding", 0, time.Minute)
	call("oc", "k3", "kimi-for-coding", 0, 2*time.Minute)
	call("oc", "k3", "openrouter", 0.2, 3*time.Minute)
	call("cx", "gpt-5.6-sol", "custom", 0, time.Minute)
	call("cx", "", "", 0, 2*time.Minute)

	kind := int(event.KindModelCall)
	var providers []string
	for _, e := range s.QueryEvents(EventFilter{Kind: &kind, Limit: 10}) {
		providers = append(providers, e.Provider)
	}
	if strings.Join(providers, ",") != ",custom,openrouter,kimi-for-coding,kimi-for-coding" {
		t.Fatalf("stored providers (newest first) = %q", providers)
	}

	// A <synthetic> row stored before ingest dropped them is not a model call.
	call("oc", "<synthetic>", "", 0, 4*time.Minute)

	rep := s.CostReport(now.Add(-time.Hour), now, "model", CostOptions{})
	byModel := costRowsByKey(rep.Rows)
	if _, ok := byModel["<synthetic>"]; ok || rep.Total.Calls != 5 || rep.Total.Unpriced != 4 {
		t.Fatalf("<synthetic> counted: total %+v rows %+v", rep.Total, rep.Rows)
	}
	if r := byModel["k3"]; r.Provider != "kimi-for-coding" || r.Calls != 3 || r.Unpriced != 2 {
		t.Fatalf("k3 row = %+v, want dominant provider kimi-for-coding, 3 calls, 2 unpriced", r)
	}
	if r := byModel["(unknown)"]; r.Provider != "" {
		t.Fatalf("(unknown) row provider = %q, want empty", r.Provider)
	}
	type g struct {
		key, model, provider string
		calls                int
	}
	var got []g
	for _, x := range rep.Groups {
		got = append(got, g{x.Key, x.Model, x.Provider, x.Calls})
	}
	want := []g{{"k3", "k3", "kimi-for-coding", 2}, {"(unknown)", "", "", 1}, {"gpt-5.6-sol", "gpt-5.6-sol", "custom", 1}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("groups = %+v, want %+v", got, want)
	}
	byHarness := s.CostReport(now.Add(-time.Hour), now, "harness", CostOptions{})
	if n := len(byHarness.Groups); n != 3 || byHarness.Groups[0].Key != "opencode" {
		t.Fatalf("by=harness groups = %+v, want opencode first of 3", byHarness.Groups)
	}
	if raw, _ := json.Marshal(rep); strings.Contains(string(raw), `"groups"`) || strings.Contains(string(raw), `"Groups"`) {
		t.Fatalf("groups are internal, not on the wire: %s", raw)
	}
}

// by=day buckets on the local calendar day: two calls either side of local
// midnight at UTC-4 are two days there and one day in UTC.
func TestCostReportByDayLocalOffset(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	for _, ts := range []string{"2026-09-23T03:30:00Z", "2026-09-23T04:30:00Z"} {
		at, _ := time.Parse(time.RFC3339, ts)
		s.PutEvent(event.Event{Kind: event.KindModelCall, TS: at, SessionID: "s1", Model: "m1", CostUSD: 1})
	}
	since, _ := time.Parse(time.RFC3339, "2026-09-22T00:00:00Z")
	until := since.Add(48 * time.Hour)
	keys := func(rep CostReport) string {
		var k []string
		for _, r := range rep.Rows {
			k = append(k, r.Key+"="+strconv.Itoa(r.Calls))
		}
		return strings.Join(k, ",")
	}
	if got := keys(s.CostReport(since, until, "day", CostOptions{TZMinutes: -240})); got != "2026-09-22=1,2026-09-23=1" {
		t.Fatalf("tz -240 rows = %s", got)
	}
	if got := keys(s.CostReport(since, until, "day", CostOptions{})); got != "2026-09-23=2" {
		t.Fatalf("tz 0 rows = %s", got)
	}
	if got := keys(s.CostReport(since, until, "day", CostOptions{TZMinutes: 9999})); got != "2026-09-23=2" {
		t.Fatalf("out-of-range tz rows = %s, want the UTC day", got)
	}
}

// by=day rows run oldest first whatever each day cost.
func TestCostReportDayRowsAscending(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	since, _ := time.Parse(time.RFC3339, "2026-09-20T00:00:00Z")
	for i, cost := range []float64{1, 5, 3} {
		s.PutEvent(event.Event{Kind: event.KindModelCall, TS: since.Add(time.Duration(i)*24*time.Hour + time.Hour),
			SessionID: "s1", Model: "m1", CostUSD: cost})
	}
	rep := s.CostReport(since, since.Add(72*time.Hour), "day", CostOptions{})
	var got []string
	for _, r := range rep.Rows {
		got = append(got, r.Key)
	}
	if strings.Join(got, ",") != "2026-09-20,2026-09-21,2026-09-22" || rep.By != "day" {
		t.Fatalf("by=%s day rows = %v, want ascending", rep.By, got)
	}
	if !near(rep.Rows[1].CostUSD, 5) || !near(rep.Total.CostUSD, 9) {
		t.Fatalf("day costs = %+v total %+v", rep.Rows, rep.Total)
	}
}

// by=provider: a recorded provider is kept, an unrecorded one is named by the
// resolver from the model id, anything else is (unknown); Sessions counts
// distinct sessions per provider and the unpriced groups share the key.
func TestCostReportByProviderResolvesVendor(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	now := time.Now()
	n := 0
	call := func(sid, mdl, provider string, cost float64) {
		n++ // model calls dedupe on (session, ts)
		s.PutEvent(event.Event{Kind: event.KindModelCall, TS: now.Add(-time.Duration(n) * time.Second), SessionID: sid,
			Model: mdl, Provider: provider, TokensIn: 10, CostUSD: cost})
	}
	call("s1", "claude-opus-5-5", "", 1)
	call("s1", "claude-opus-5-5", "", 1)
	call("s2", "claude-opus-5-5", "", 1)
	call("s2", "gpt-5", "openai-codex", 0.5)
	call("s3", "gpt-5", "", 0.25)
	call("s3", "k3", "", 0)
	call("s1", "k3", "", 0)
	call("s3", "", "", 0)
	vendors := map[string]string{"claude-opus-5-5": "anthropic", "gpt-5": "openai"}
	resolve := func(m string) string { return vendors[m] }

	rep := s.CostReport(now.Add(-time.Hour), now, "provider", CostOptions{ProviderFor: resolve})
	rows := costRowsByKey(rep.Rows)
	for key, want := range map[string][3]float64{ // calls, sessions, cost
		"anthropic":    {3, 2, 3},
		"openai-codex": {1, 1, 0.5},
		"openai":       {1, 1, 0.25},
		"(unknown)":    {3, 2, 0},
	} {
		r, ok := rows[key]
		if !ok || float64(r.Calls) != want[0] || float64(r.Sessions) != want[1] || !near(r.CostUSD, want[2]) {
			t.Errorf("row %s = %+v, want calls/sessions/cost %v", key, r, want)
		}
	}
	if len(rep.Rows) != 4 || rep.By != "provider" || rep.Total.Calls != 8 {
		t.Fatalf("by=%s rows=%+v total=%+v", rep.By, rep.Rows, rep.Total)
	}
	for _, g := range rep.Groups {
		if g.Key != "(unknown)" {
			t.Fatalf("unpriced group key %q, want (unknown)", g.Key)
		}
	}

	bare := costRowsByKey(s.CostReport(now.Add(-time.Hour), now, "provider", CostOptions{}).Rows)
	if bare["(unknown)"].Calls != 7 || bare["openai-codex"].Calls != 1 || len(bare) != 2 {
		t.Fatalf("no resolver rows = %+v, want recorded provider or (unknown)", bare)
	}
}
