package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestCostsServedFromCacheForSameParameters(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	now := time.Now()
	st.UpsertSession(model.Session{ID: "s1", Harness: "claude", Repo: "A", StartedAt: now, LastSeenAt: now})
	call := func(ago time.Duration, mdl string, cost float64) {
		st.PutEvent(event.Event{Kind: event.KindModelCall, TS: now.Add(-ago), SessionID: "s1", Model: mdl, TokensIn: 10, CostUSD: cost})
	}
	call(time.Hour, "claude-sonnet-4-5", 0.5)
	call(time.Hour+time.Minute, "", 0)

	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	clock := now
	a.costs.now = func() time.Time { return clock }
	mux := a.buildMux()
	// An explicit window keeps the key fixed however long the test runs.
	window := "since=" + url.QueryEscape(now.Add(-2*time.Hour).Format(time.RFC3339)) +
		"&until=" + url.QueryEscape(now.Add(time.Hour).Format(time.RFC3339))
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
	calls := func(path string) int {
		t.Helper()
		var rep store.CostReport
		get(path, &rep)
		return rep.Total.Calls
	}
	unpriced := func() int {
		t.Helper()
		var out unpricedCostReport
		get("/costs/unpriced?"+window, &out)
		n := 0
		for _, r := range out.Rows {
			n += r.Calls
		}
		return n
	}

	if got := calls("/costs?by=model&" + window); got != 2 {
		t.Fatalf("first report: %d calls, want 2", got)
	}
	if got := unpriced(); got != 1 {
		t.Fatalf("first unpriced report: %d calls, want 1", got)
	}
	call(30*time.Minute, "", 0)
	if got := calls("/costs?by=model&" + window); got != 2 {
		t.Fatalf("same parameters within the TTL: %d calls, want the cached 2", got)
	}
	if got := unpriced(); got != 1 {
		t.Fatalf("unpriced within the TTL: %d calls, want the cached 1", got)
	}
	if got := calls("/costs?by=repo&" + window); got != 3 {
		t.Fatalf("different grouping: %d calls, want a fresh 3", got)
	}
	if got := calls("/costs?by=model&tz=60&" + window); got != 3 {
		t.Fatalf("different tz: %d calls, want a fresh 3", got)
	}
	clock = clock.Add(costCacheTTL)
	if got := calls("/costs?by=model&" + window); got != 3 {
		t.Fatalf("after the TTL: %d calls, want a fresh 3", got)
	}
	if got := unpriced(); got != 2 {
		t.Fatalf("unpriced after the TTL: %d calls, want a fresh 2", got)
	}
}

func TestCostKeyRoundsWindowToTheMinute(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 5, 0, time.UTC)
	same := costKey("costs", "repo", t0.Add(-24*time.Hour), t0, 0)
	if k := costKey("costs", "repo", t0.Add(40*time.Second-24*time.Hour), t0.Add(40*time.Second), 0); k != same {
		t.Fatalf("same minute: %q != %q", k, same)
	}
	for _, k := range []string{
		costKey("costs", "repo", t0.Add(time.Minute-24*time.Hour), t0.Add(time.Minute), 0),
		costKey("costs", "model", t0.Add(-24*time.Hour), t0, 0),
		costKey("costs", "repo", t0.Add(-24*time.Hour), t0, 60),
		costKey("unpriced", "repo", t0.Add(-24*time.Hour), t0, 0),
	} {
		if k == same {
			t.Fatalf("distinct parameters share key %q", k)
		}
	}
}

func TestCostCacheConcurrentAndBounded(t *testing.T) {
	var c costCache
	var computed atomic.Int32
	release := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v := c.get("k", func() any {
				computed.Add(1)
				<-release
				return 42
			})
			if v != 42 {
				t.Errorf("value = %v", v)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if n := computed.Load(); n != 1 {
		t.Fatalf("16 concurrent requests computed %d times, want 1", n)
	}

	for i := 0; i < 3*costCacheMax; i++ {
		k := fmt.Sprint(i)
		c.get(k, func() any { return k })
	}
	c.mu.Lock()
	n := len(c.entries)
	_, newest := c.entries[fmt.Sprint(3*costCacheMax-1)]
	c.mu.Unlock()
	if n > costCacheMax || !newest {
		t.Fatalf("entries = %d (newest kept %v), want at most %d", n, newest, costCacheMax)
	}

	// A compute that panics is not cached: the next request computes.
	func() {
		defer func() { _ = recover() }()
		c.get("boom", func() any { panic("x") })
	}()
	if v := c.get("boom", func() any { return "ok" }); v != "ok" {
		t.Fatalf("after a panic: %v", v)
	}
}

func TestCostsConcurrentRequestsRaceFree(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	now := time.Now()
	st.UpsertSession(model.Session{ID: "s1", Harness: "claude", Repo: "A", StartedAt: now, LastSeenAt: now})
	st.PutEvent(event.Event{Kind: event.KindModelCall, TS: now.Add(-time.Hour), SessionID: "s1", Model: "m1", CostUSD: 0.5})
	mux := newTestAPI("", st, nil, func() Status { return Status{Running: true} }).buildMux()
	paths := []string{"/costs", "/costs?by=model", "/costs?by=day&tz=120", "/costs/unpriced", "/costs?since=7d"}
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
			if rec.Code != http.StatusOK {
				t.Errorf("%s: status %d", p, rec.Code)
			}
		}(paths[i%len(paths)])
	}
	wg.Wait()
}
