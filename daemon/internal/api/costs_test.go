package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestCostsEndpoint(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	now := time.Now()
	st.UpsertSession(model.Session{ID: "s1", Harness: "claude", Repo: "A", Branch: "main", StartedAt: now, LastSeenAt: now})
	st.PutEvent(event.Event{Kind: event.KindModelCall, TS: now.Add(-time.Hour), SessionID: "s1", Model: "m1", CostUSD: 0.5})
	st.PutEvent(event.Event{Kind: event.KindModelCall, TS: now.Add(-3 * 24 * time.Hour), SessionID: "s1", Model: "m1", CostUSD: 2})
	mux := newTestAPI("", st, nil, func() Status { return Status{Running: true} }).buildMux()

	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}
	decode := func(rec *httptest.ResponseRecorder) store.CostReport {
		t.Helper()
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
		}
		var rep store.CostReport
		if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
			t.Fatal(err)
		}
		return rep
	}

	def := decode(get("/costs"))
	if def.By != "repo" || len(def.Rows) != 1 || def.Rows[0].Key != "A" || def.Rows[0].Harness != "claude" || def.Total.CostUSD != 0.5 {
		t.Fatalf("default (24h, by repo) = %+v", def)
	}
	week := decode(get("/costs?since=7d&by=model"))
	if week.By != "model" || week.Total.Calls != 2 || week.Total.CostUSD != 2.5 {
		t.Fatalf("since=7d by=model = %+v", week)
	}
	abs := decode(get("/costs?since=" + now.Add(-4*24*time.Hour).UTC().Format(time.RFC3339) +
		"&until=" + now.Add(-2*24*time.Hour).UTC().Format(time.RFC3339)))
	if abs.Total.Calls != 1 || abs.Total.CostUSD != 2 {
		t.Fatalf("RFC3339 window = %+v, want only the 3-day-old call", abs)
	}

	for _, bad := range []string{"/costs?by=nope", "/costs?since=garbage", "/costs?since=-5h", "/costs?until=yesterday"} {
		if rec := get(bad); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", bad, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/costs", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /costs: status %d, want 405", rec.Code)
	}
}

// Every unpriced call is explained: /costs splits unpriced_calls into
// unknown-model, unpriced-model, plan and local counters (rows and total),
// by=model rows carry provider and class, and /costs/unpriced lists what is
// left to price.
func TestCostsClassifyUnpricedCalls(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	now := time.Now()
	for _, s := range []model.Session{{ID: "cl", Harness: "claude"}, {ID: "oc", Harness: "opencode"}, {ID: "cx", Harness: "codex"}} {
		s.StartedAt, s.LastSeenAt = now, now
		st.UpsertSession(s)
	}
	n := 0
	call := func(sid, mdl, provider string, cost float64) {
		n++
		st.PutEvent(event.Event{Kind: event.KindModelCall, TS: now.Add(-time.Duration(n) * time.Minute), SessionID: sid,
			Model: mdl, Provider: provider, TokensIn: 100, TokensOut: 10, CostUSD: cost})
	}
	call("cl", "claude-sonnet-4-5", "", 0.5) // priced
	call("oc", "k3", "kimi-for-coding", 0)   // plan
	call("oc", "k3", "kimi-for-coding", 0)   // plan
	call("oc", "llama3.1:8b", "ollama", 0)   // local
	call("cx", "", "", 0)                    // unknown-model
	call("cx", "gpt-5.6-sol", "custom", 0)   // unpriced-model
	mux := newTestAPI("", st, nil, func() Status { return Status{Running: true} }).buildMux()
	get := func(path string, v any) {
		t.Helper()
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d body %q", path, rec.Code, rec.Body.String())
		}
		if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
			t.Fatal(err)
		}
	}

	var byModel store.CostReport
	get("/costs?by=model", &byModel)
	tot := byModel.Total
	if tot.Unpriced != 5 || tot.UnknownModel != 1 || tot.UnpricedModel != 1 || tot.Plan != 2 || tot.Local != 1 {
		t.Fatalf("total = %+v, want unpriced 5 = unknown 1 + unpriced-model 1 + plan 2 + local 1", tot)
	}
	rows := map[string]store.CostRow{}
	for _, r := range byModel.Rows {
		rows[r.Key] = r
	}
	for key, want := range map[string][2]string{
		"claude-sonnet-4-5": {"", "priced"},
		"k3":                {"kimi-for-coding", "plan"},
		"llama3.1:8b":       {"ollama", "local"},
		"(unknown)":         {"", "unknown-model"},
		"gpt-5.6-sol":       {"custom", "unpriced-model"},
	} {
		if r := rows[key]; r.Provider != want[0] || r.Class != want[1] {
			t.Errorf("row %s = provider %q class %q, want %q %q", key, r.Provider, r.Class, want[0], want[1])
		}
	}
	if r := rows["k3"]; r.Plan != 2 || r.Unpriced != 2 {
		t.Errorf("k3 row counters = %+v", r)
	}

	var byHarness store.CostReport
	get("/costs?by=harness", &byHarness)
	for _, r := range byHarness.Rows {
		if r.Key == "codex" && (r.UnknownModel != 1 || r.UnpricedModel != 1 || r.Class != "") {
			t.Errorf("codex row = %+v, want 1 unknown + 1 unpriced-model and no class", r)
		}
	}

	var unpriced struct {
		Since string `json:"since"`
		Rows  []struct {
			Harness   string `json:"harness"`
			Provider  string `json:"provider"`
			Model     string `json:"model"`
			Class     string `json:"class"`
			Calls     int    `json:"calls"`
			TokensIn  int64  `json:"tokens_in"`
			TokensOut int64  `json:"tokens_out"`
		} `json:"rows"`
	}
	get("/costs/unpriced?since=24h", &unpriced)
	var got []string
	for _, r := range unpriced.Rows {
		got = append(got, fmt.Sprintf("%s|%s|%s|%s|%d|%d|%d", r.Harness, r.Provider, r.Model, r.Class, r.Calls, r.TokensIn, r.TokensOut))
	}
	want := []string{
		"opencode|kimi-for-coding|k3|plan|2|200|20",
		"codex|||unknown-model|1|100|10",
		"codex|custom|gpt-5.6-sol|unpriced-model|1|100|10",
		"opencode|ollama|llama3.1:8b|local|1|100|10",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("/costs/unpriced rows =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !apiroutes.ConsoleAllowed("/costs/unpriced") {
		t.Fatal("/costs/unpriced must be admitted for the console")
	}
	for _, bad := range []string{"/costs/unpriced?since=garbage", "/costs/unpriced?until=yesterday"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, bad, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", bad, rec.Code)
		}
	}
}
