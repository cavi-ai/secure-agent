package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
