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

	a := newCostsTestAPI(t, st)
	clock := now
	a.costs.now = func() time.Time { return clock }
	a.unpriced.now = a.costs.now
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

func TestCostKeyIsTheRequestAsAsked(t *testing.T) {
	same := costKey("costs", "repo", "24h", "", 0)
	if k := costKey("costs", "repo", "24h", "", 0); k != same {
		t.Fatalf("same parameters: %q != %q", k, same)
	}
	for _, k := range []string{
		costKey("costs", "repo", "7d", "", 0),
		costKey("costs", "model", "24h", "", 0),
		costKey("costs", "repo", "24h", "", 60),
		costKey("costs", "repo", "24h", "2026-09-25T10:00:00Z", 0),
		costKey("unpriced", "repo", "24h", "", 0),
	} {
		if k == same {
			t.Fatalf("distinct parameters share key %q", k)
		}
	}

	// A lookback asked again is the report already computed, whatever the
	// clock: the key does not move with the window.
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	now := time.Now()
	st.UpsertSession(model.Session{ID: "s1", Harness: "claude", Repo: "A", StartedAt: now, LastSeenAt: now})
	st.PutEvent(event.Event{Kind: event.KindModelCall, TS: now.Add(-time.Hour), SessionID: "s1", Model: "m", CostUSD: 0.5})
	a := newCostsTestAPI(t, st)
	clock := now
	a.costs.now = func() time.Time { return clock }
	mux := a.buildMux()
	if rep := getCosts(t, mux, "/costs"); rep.Total.Calls != 1 {
		t.Fatalf("first: %d calls, want 1", rep.Total.Calls)
	}
	st.PutEvent(event.Event{Kind: event.KindModelCall, TS: now.Add(-time.Minute), SessionID: "s1", Model: "m", CostUSD: 0.5})
	clock = clock.Add(costCacheTTL - time.Second)
	if rep := getCosts(t, mux, "/costs?since=24h"); rep.Total.Calls != 1 {
		t.Fatalf("the default window asked as 24h within the TTL: %d calls, want the cached 1", rep.Total.Calls)
	}
}

// newCostsTestAPI builds the API on st; the test waits for the report
// cache's background work before st closes.
func newCostsTestAPI(t *testing.T, st *store.Store) *API {
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	t.Cleanup(a.costs.bg.Wait)
	return a
}

// getCosts GETs a /costs path and decodes the report.
func getCosts(t *testing.T, mux http.Handler, path string) store.CostReport {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status %d body %q", path, rec.Code, rec.Body.String())
	}
	var rep store.CostReport
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestCostsCachedAnswersAtOnceAndRefreshesInTheBackground(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	now := time.Now()
	st.UpsertSession(model.Session{ID: "s1", Harness: "claude", Repo: "A", StartedAt: now, LastSeenAt: now})
	calls := 0
	call := func() { // one more model call, a minute apart (identical rows are one)
		calls++
		st.PutEvent(event.Event{Kind: event.KindModelCall, TS: now.Add(-time.Duration(calls) * time.Minute), SessionID: "s1", Model: "m", CostUSD: 0.5})
	}
	call()
	a := newCostsTestAPI(t, st)
	clock := now
	a.costs.now = func() time.Time { return clock }
	mux := a.buildMux()

	first := getCosts(t, mux, "/costs?cached=1")
	if first.Total.Calls != 1 || first.Refreshing || first.GeneratedAt != now.UTC().Format(time.RFC3339) {
		t.Fatalf("first cached=1 request computes and waits: %+v", first)
	}
	call()
	clock = clock.Add(costCacheTTL)
	stale := getCosts(t, mux, "/costs?cached=1")
	if stale.Total.Calls != 1 || !stale.Refreshing || stale.GeneratedAt != first.GeneratedAt {
		t.Fatalf("past the TTL, cached=1 answers the last report and refreshes: %+v", stale)
	}
	a.costs.bg.Wait()
	fresh := getCosts(t, mux, "/costs?cached=1")
	if fresh.Total.Calls != 2 || fresh.Refreshing || fresh.GeneratedAt != clock.UTC().Format(time.RFC3339) {
		t.Fatalf("after the refresh: %+v", fresh)
	}

	call()
	clock = clock.Add(costCacheTTL)
	if rep := getCosts(t, mux, "/costs"); rep.Total.Calls != 3 || rep.Refreshing {
		t.Fatalf("without cached=1, a report past the TTL is computed and waited for: %+v", rep)
	}
}

func TestCostsCacheSurvivesARestart(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	now := time.Now()
	st.UpsertSession(model.Session{ID: "s1", Harness: "claude", Repo: "A", StartedAt: now, LastSeenAt: now})
	calls := 0
	call := func() { // one more model call, a minute apart (identical rows are one)
		calls++
		st.PutEvent(event.Event{Kind: event.KindModelCall, TS: now.Add(-time.Duration(calls) * time.Minute), SessionID: "s1", Model: "m", CostUSD: 0.5})
	}
	call()
	before := newCostsTestAPI(t, st)
	before.costs.now = func() time.Time { return now }
	saved := getCosts(t, before.buildMux(), "/costs?by=model&cached=1")
	before.costs.bg.Wait()
	call()

	// The next run: the saved report answers a cached=1 request at once,
	// and one asked without cached=1 is computed.
	after := newCostsTestAPI(t, st)
	after.costs.now = func() time.Time { return now.Add(time.Hour) }
	mux := after.buildMux()
	rep := getCosts(t, mux, "/costs?by=model&cached=1")
	if rep.Total.Calls != 1 || !rep.Refreshing || rep.GeneratedAt != saved.GeneratedAt || len(rep.Rows) != 1 || rep.Rows[0].Class != saved.Rows[0].Class {
		t.Fatalf("restored report: %+v, saved %+v", rep, saved)
	}
	after.costs.bg.Wait()
	if rep := getCosts(t, mux, "/costs?by=model&cached=1"); rep.Total.Calls != 2 || rep.Refreshing {
		t.Fatalf("after the refresh: %+v", rep)
	}
	if rep := getCosts(t, mux, "/costs?by=repo"); rep.Total.Calls != 2 || rep.Refreshing {
		t.Fatalf("not saved before: computed: %+v", rep)
	}

	// A saved row that does not decode is ignored.
	st.PutScanCache(costsCacheName, []byte("{"), now)
	broken := newCostsTestAPI(t, st)
	if rep := getCosts(t, broken.buildMux(), "/costs?by=model&cached=1"); rep.Total.Calls != 2 || rep.Refreshing {
		t.Fatalf("corrupt saved reports: %+v", rep)
	}
}

func TestCostCacheConcurrentAndBounded(t *testing.T) {
	var c costCache[any]
	var computed atomic.Int32
	release := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, _, _ := c.get("k", i%2 == 0, func() any {
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
		c.get(k, false, func() any { return k })
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
		c.get("boom", false, func() any { panic("x") })
	}()
	if v, _, _ := c.get("boom", false, func() any { return "ok" }); v != "ok" {
		t.Fatalf("after a panic: %v", v)
	}
}

func TestCostCacheBackgroundRefreshSharedAndPanicSafe(t *testing.T) {
	clock := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	c := costCache[int]{now: func() time.Time { return clock }}
	c.get("k", false, func() int { return 1 })
	clock = clock.Add(costCacheTTL)

	var computed atomic.Int32
	release := make(chan struct{})
	for i := 0; i < 16; i++ {
		v, at, refreshing := c.get("k", true, func() int {
			computed.Add(1)
			<-release
			return 2
		})
		if v != 1 || !refreshing || !at.Equal(clock.Add(-costCacheTTL)) {
			t.Fatalf("stale request %d: %d %v %v", i, v, at, refreshing)
		}
	}
	close(release)
	c.bg.Wait()
	if n := computed.Load(); n != 1 {
		t.Fatalf("16 stale requests refreshed %d times, want 1", n)
	}
	if v, _, refreshing := c.get("k", true, func() int { return 3 }); v != 2 || refreshing {
		t.Fatalf("after the refresh: %d %v", v, refreshing)
	}

	// A background compute that panics keeps the report held and the next
	// stale request refreshes again.
	clock = clock.Add(costCacheTTL)
	if v, _, _ := c.get("k", true, func() int { panic("x") }); v != 2 {
		t.Fatalf("stale value = %d", v)
	}
	c.bg.Wait()
	if v, _, refreshing := c.get("k", true, func() int { return 4 }); v != 2 || !refreshing {
		t.Fatalf("after a panicked refresh: %d %v", v, refreshing)
	}
	c.bg.Wait()
	if v, _, _ := c.get("k", true, func() int { return 5 }); v != 4 {
		t.Fatalf("after the next refresh: %d", v)
	}
}

func TestCostsConcurrentRequestsRaceFree(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	now := time.Now()
	st.UpsertSession(model.Session{ID: "s1", Harness: "claude", Repo: "A", StartedAt: now, LastSeenAt: now})
	st.PutEvent(event.Event{Kind: event.KindModelCall, TS: now.Add(-time.Hour), SessionID: "s1", Model: "m1", CostUSD: 0.5})
	mux := newCostsTestAPI(t, st).buildMux()
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
