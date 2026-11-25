package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// cacheTestAPI is an API over a fresh store whose clock reads *clock.
func cacheTestAPI(t *testing.T, clock *time.Time) (*API, Deps) {
	t.Helper()
	deps := explainTestDeps(t)
	a := newTestAPI(deps)
	a.flagReads.now = func() time.Time { return *clock }
	return a, deps
}

func cacheTestClock() time.Time { return time.Now().UTC().Truncate(time.Minute).Add(5 * time.Second) }

func getBody(a *API, path string) ([]byte, error) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if path == "/posture" {
		a.handlePosture(rec, req)
	} else {
		a.handleSnapshot(rec, req)
	}
	if rec.Code != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %d %s", path, rec.Code, rec.Body)
	}
	return rec.Body.Bytes(), nil
}

func mustGet(t *testing.T, a *API, path string) []byte {
	t.Helper()
	body, err := getBody(a, path)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

type snapshotView struct {
	Flags []struct {
		ID      string `json:"id"`
		Advisor *struct {
			Rationale string `json:"rationale"`
		} `json:"advisor"`
	} `json:"flags"`
	Events []struct {
		Detail string `json:"detail"`
	} `json:"events"`
	Sessions []struct {
		ID string `json:"id"`
	} `json:"sessions"`
	Incidents []struct {
		ID string `json:"id"`
	} `json:"incidents"`
	Reviews struct {
		Reviews []struct {
			ID          string `json:"id"`
			ReviewState string `json:"review_state"`
		} `json:"reviews"`
	} `json:"reviews"`
}

func decodeSnapshot(body []byte) (snapshotView, error) {
	var v snapshotView
	err := json.Unmarshal(body, &v)
	return v, err
}

// populateSnapshotStore writes a session, an event, an incident, a finding
// review and acknowledged or old flags: no unacted flag is in the 24 h window.
func populateSnapshotStore(t *testing.T, a *API, now time.Time) {
	t.Helper()
	st := a.store
	if err := st.UpsertSession(model.Session{ID: "s-pop", Harness: "claude", Workspace: "/repo"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PutEvent(event.Event{Kind: event.KindFileOpen, PID: 30, TS: now, Detail: "pop"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PutFlag(keychainFlag("ack", "codex", 31, now.Add(-time.Minute), 3)); err != nil {
		t.Fatal(err)
	}
	st.AcknowledgeFlag("ack")
	old := liveFixtureFlag()
	if _, err := st.PutFlag(old); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ObserveFindingReview(old, model.AssessFinding(old)); err != nil {
		t.Fatal(err)
	}
	if err := st.PutIncident(model.IncidentReport{ID: "inc-pop", FlagID: old.ID, Rule: old.Rule, Timestamp: now}); err != nil {
		t.Fatal(err)
	}
}

func statementsDuring(a *API, f func()) uint64 {
	before := a.store.StatementCount()
	f()
	return a.store.StatementCount() - before
}

// liveStatements counts the statements one snapshot runs for its uncached
// inputs: live status for the response and for posture.
func liveStatements(a *API) uint64 {
	return statementsDuring(a, func() {
		a.currentStatus()
		a.evidenceStatus(a.statusFn())
	})
}

func TestSnapshotRepeatRunsNoStoreQueryForCachedReads(t *testing.T) {
	clock := cacheTestClock()
	a, _ := cacheTestAPI(t, &clock)
	populateSnapshotStore(t, a, clock)
	first := statementsDuring(a, func() { mustGet(t, a, "/snapshot") })
	second := statementsDuring(a, func() { mustGet(t, a, "/snapshot") })
	live := liveStatements(a)
	if first <= live || second != live {
		t.Fatalf("statements: first %d, second %d, live status alone %d; want second == live < first", first, second, live)
	}
}

// Each write is in the next response, and the response served from the cache
// afterwards equals one computed by an API with an empty cache.
func TestSnapshotReflectsEachStoreWrite(t *testing.T) {
	clock := cacheTestClock()
	a, deps := cacheTestAPI(t, &clock)
	populateSnapshotStore(t, a, clock)
	st := a.store
	reviewed := liveFixtureFlag()
	reviewed.ID = "w-review"
	if _, err := st.PutFlag(reviewed); err != nil {
		t.Fatal(err)
	}
	review, err := st.ObserveFindingReview(reviewed, model.AssessFinding(reviewed))
	if err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		name  string
		write func() error
		shows func(snapshotView) bool
	}{
		{"flag", func() error {
			_, err := st.PutFlag(keychainFlag("w-flag", "codex", 41, clock.Add(-time.Minute), 2))
			return err
		}, func(v snapshotView) bool {
			for _, f := range v.Flags {
				if f.ID == "w-flag" {
					return true
				}
			}
			return false
		}},
		{"advisor verdict", func() error {
			return st.PutAdvisorVerdict("w-flag", "flag", model.AdvisorVerdict{Rationale: "checked", CreatedAt: clock})
		}, func(v snapshotView) bool {
			for _, f := range v.Flags {
				if f.ID == "w-flag" {
					return f.Advisor != nil && f.Advisor.Rationale == "checked"
				}
			}
			return false
		}},
		{"event", func() error {
			_, err := st.PutEvent(event.Event{Kind: event.KindProxyHit, PID: 42, TS: clock, Detail: "w-event"})
			return err
		}, func(v snapshotView) bool {
			for _, e := range v.Events {
				if e.Detail == "w-event" {
					return true
				}
			}
			return false
		}},
		{"session", func() error {
			return st.UpsertSession(model.Session{ID: "w-session", Harness: "codex", Workspace: "/w"})
		}, func(v snapshotView) bool {
			for _, s := range v.Sessions {
				if s.ID == "w-session" {
					return true
				}
			}
			return false
		}},
		{"incident", func() error {
			return st.PutIncident(model.IncidentReport{ID: "w-incident", FlagID: "w-flag", Rule: "keychain-access", Timestamp: clock})
		}, func(v snapshotView) bool {
			for _, inc := range v.Incidents {
				if inc.ID == "w-incident" {
					return true
				}
			}
			return false
		}},
		{"finding review decision", func() error {
			_, err := st.DecideFindingReview(model.ReviewDecisionRequest{ID: review.ID, Revision: review.Revision, Action: "acknowledge"})
			return err
		}, func(v snapshotView) bool {
			for _, r := range v.Reviews.Reviews {
				if r.ID == review.ID {
					return r.ReviewState != review.ReviewState
				}
			}
			return true
		}},
		{"acknowledgement", func() error {
			if !st.AcknowledgeFlag("w-flag") {
				return fmt.Errorf("w-flag not acknowledged")
			}
			return nil
		}, func(v snapshotView) bool {
			for _, f := range v.Flags {
				if f.ID == "w-flag" {
					return false
				}
			}
			return true
		}},
	}
	for _, step := range steps {
		before := mustGet(t, a, "/snapshot")
		if err := step.write(); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		after := mustGet(t, a, "/snapshot")
		v, err := decodeSnapshot(after)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(before, after) || !step.shows(v) {
			t.Fatalf("%s: write missing from the next snapshot: %s", step.name, after)
		}
		cached := mustGet(t, a, "/snapshot")
		fresh := mustGet(t, cacheFreeAPI(deps, &clock), "/snapshot")
		if !bytes.Equal(cached, fresh) {
			t.Fatalf("%s: cached snapshot differs from a fresh one:\ncached %s\nfresh  %s", step.name, cached, fresh)
		}
	}
}

func cacheFreeAPI(deps Deps, clock *time.Time) *API {
	a := newTestAPI(deps)
	a.flagReads.now = func() time.Time { return *clock }
	return a
}

func TestPostureReflectsFlagWrite(t *testing.T) {
	clock := cacheTestClock()
	a, deps := cacheTestAPI(t, &clock)
	needsYou := func(body []byte) int {
		var p struct {
			NeedsYou int `json:"needs_you"`
		}
		if err := json.Unmarshal(body, &p); err != nil {
			t.Fatal(err)
		}
		return p.NeedsYou
	}
	before := mustGet(t, a, "/posture")
	if again := mustGet(t, a, "/posture"); !bytes.Equal(before, again) {
		t.Fatalf("repeat posture differs:\n%s\n%s", before, again)
	}
	if _, err := a.store.PutFlag(keychainFlag("p-flag", "codex", 51, clock.Add(-time.Minute), 3)); err != nil {
		t.Fatal(err)
	}
	after := mustGet(t, a, "/posture")
	if needsYou(after) <= needsYou(before) || !bytes.Contains(after, []byte("p-flag")) {
		t.Fatalf("flag missing from posture:\nbefore %s\nafter  %s", before, after)
	}
	if fresh := mustGet(t, cacheFreeAPI(deps, &clock), "/posture"); !bytes.Equal(mustGet(t, a, "/posture"), fresh) {
		t.Fatalf("cached posture differs from a fresh one")
	}
}

// An entry is served until it is storeReadMaxAge old or the 24 h window moves
// to the next minute, whichever comes first.
func TestSnapshotCacheDropsEntriesPastTheBound(t *testing.T) {
	clock := cacheTestClock()
	start := clock
	a, _ := cacheTestAPI(t, &clock)
	populateSnapshotStore(t, a, clock)
	mustGet(t, a, "/snapshot")
	live := liveStatements(a)
	at := func(when time.Time, cached bool) {
		t.Helper()
		clock = when
		n := statementsDuring(a, func() { mustGet(t, a, "/snapshot") })
		if (n == live) != cached {
			t.Fatalf("at +%s: %d statements, live status alone %d, want cached %v", when.Sub(start), n, live, cached)
		}
	}
	at(start.Add(storeReadMaxAge-time.Nanosecond), true)
	at(start.Add(storeReadMaxAge), false)
	at(start.Add(storeReadMaxAge+time.Second), true)
	minuteEnd := start.Truncate(time.Minute).Add(time.Minute - time.Second)
	at(minuteEnd, false)
	at(minuteEnd.Add(2*time.Second), false)
}

// Readers running beside a writer never get a snapshot older than the last
// write completed before their request started.
func TestSnapshotReadersSeeEveryCompletedWrite(t *testing.T) {
	clock := cacheTestClock()
	a, _ := cacheTestAPI(t, &clock)
	const writes = 60
	var done atomic.Int64
	writerDone := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(writerDone)
		for i := range writes {
			if _, err := a.store.PutFlag(keychainFlag(fmt.Sprintf("r%03d", i), "codex", 7, clock.Add(-time.Duration(i+1)*time.Second), 3)); err != nil {
				t.Error(err)
				return
			}
			done.Store(int64(i + 1))
		}
	}()
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				finished := false
				select {
				case <-writerDone:
					finished = true
				default:
				}
				want := done.Load()
				body, err := getBody(a, "/snapshot")
				if err != nil {
					t.Error(err)
					return
				}
				v, err := decodeSnapshot(body)
				if err != nil {
					t.Error(err)
					return
				}
				if int64(len(v.Flags)) < want {
					t.Errorf("snapshot has %d flags after %d completed writes", len(v.Flags), want)
					return
				}
				if finished {
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-writerDone:
				return
			default:
			}
			if _, err := getBody(a, "/posture"); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	wg.Wait()
}
