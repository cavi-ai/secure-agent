package store

import (
	"encoding/json"
	"math"
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
	rep := s.CostReport(now.Add(-24*time.Hour), now, "repo")

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

	byModel := costRowsByKey(s.CostReport(since, now, "model").Rows)
	if len(byModel) != 3 || !near(byModel["m1"].CostUSD, 0.75) || !near(byModel["m2"].CostUSD, 0.1) ||
		byModel["(unknown)"].Unpriced != 1 || byModel["(unknown)"].CostUSD != 0 {
		t.Fatalf("by=model rows = %+v", byModel)
	}

	bySession := costRowsByKey(s.CostReport(since, now, "session").Rows)
	if len(bySession) != 3 || bySession["s1"].Calls != 2 || bySession["s2"].Calls != 1 || bySession["s3"].Calls != 1 {
		t.Fatalf("by=session rows = %+v, want s1/s2/s3", bySession)
	}
	if bySession["s3"].Harness != "codex" {
		t.Fatalf("session s3 harness = %q, want codex", bySession["s3"].Harness)
	}

	fallback := s.CostReport(since, now, "nope")
	if fallback.By != "repo" || len(fallback.Rows) != 3 || fallback.Rows[0].Key != "A" {
		t.Fatalf("unknown by must behave as repo: %+v", fallback)
	}

	byBranch := costRowsByKey(s.CostReport(since, now, "branch").Rows)
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
	rep := s.CostReport(now.Add(-24*time.Hour), now, "repo")
	if rep.Rows == nil {
		t.Fatal("Rows is nil on an empty store; must be []")
	}
	b, _ := json.Marshal(rep)
	if !strings.Contains(string(b), `"rows":[]`) {
		t.Fatalf("empty report JSON = %s, want rows: []", b)
	}
}
