package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestEgressEpisodesCandidateAndAssessment(t *testing.T) {
	st := testStore(t)
	scope := store.EgressScope{Agent: "claude", ExePath: "/usr/bin/claude", Harness: "claude", Workspace: "/work/a"}
	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		for _, host := range []string{"203.0.113.1", "203.0.113.2"} {
			at := now.Add(time.Duration(i-4) * 30 * time.Minute)
			if host == "203.0.113.2" {
				at = now.Add(time.Duration(i-4) * time.Second)
			}
			if err := st.RecordEgressObservationForTest(store.EgressObservation{Scope: scope, SessionID: "s1", Host: host, Protocol: "tcp", Port: 443, At: at}); err != nil {
				t.Fatal(err)
			}
		}
	}
	api := newTestAPI("", st, nil, nil)
	queued := 0
	api.egressAdvisor = func(store.EgressEpisode) bool { queued++; return true }
	mux := api.buildMux()
	read := func() []egressEpisodeView {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/egress/episodes", nil))
		if w.Code != 200 {
			t.Fatalf("read: %d %s", w.Code, w.Body.String())
		}
		var body struct {
			Episodes []egressEpisodeView `json:"episodes"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body.Episodes
	}
	episodes := read()
	if len(episodes) != 2 {
		t.Fatalf("episodes=%+v", episodes)
	}
	var recurring store.EgressEpisode
	for _, e := range episodes {
		if e.Observed.Host == "203.0.113.1" {
			recurring = e.Observed
			if !e.Candidate || e.Expected {
				t.Fatalf("spaced=%+v", e)
			}
		}
		if e.Observed.Host == "203.0.113.2" && e.Candidate {
			t.Fatalf("burst=%+v", e)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(method, "/egress/episodes/"+recurring.ID+"/assess", nil))
		if method == http.MethodPost && w.Code != 200 {
			t.Fatalf("assess: %d %s", w.Code, w.Body.String())
		}
		if method == http.MethodGet && w.Code != 405 {
			t.Fatalf("GET assess: %d", w.Code)
		}
	}
	if queued != 1 {
		t.Fatalf("queued=%d", queued)
	}
	assessPath := "/egress/episodes/" + recurring.ID + "/assess"
	if !apiroutes.ConsoleAllowed("POST", assessPath) || !apiroutes.IsNoAgent(assessPath) || !apiroutes.IsMutation("POST", assessPath) || apiroutes.ConsoleAllowed("POST", "/egress/episodes/bad/other") {
		t.Fatal("assess route not gated")
	}
	st.PutAdvisorVerdict(advisor.EgressSubjectID(recurring.ID), "egress", model.AdvisorVerdict{Assessment: advisor.EgressEvidenceKey(recurring), Rationale: "Possibly periodic sync", Confidence: 0.7, CreatedAt: now})
	for _, e := range read() {
		if e.Observed.ID == recurring.ID && (e.AdvisorInference == nil || e.AdvisorInference.PossiblePurpose != "Possibly periodic sync") {
			t.Fatalf("inference missing: %+v", e)
		}
	}
	wCached := httptest.NewRecorder()
	mux.ServeHTTP(wCached, httptest.NewRequest(http.MethodPost, assessPath, nil))
	if wCached.Code != 200 || queued != 1 {
		t.Fatalf("cached assessment requeued: %d, %d", wCached.Code, queued)
	}
	exact, err := st.CreateExpectedEgressRule(store.ExpectedEgressRule{Agent: "claude", Kind: "destination", Host: recurring.Host, Protocol: recurring.Protocol, Port: recurring.Port})
	if err != nil {
		t.Fatal(err)
	}
	broad, err := st.CreateExpectedEgressRule(store.ExpectedEgressRule{Agent: "claude", Kind: "scope", ExePath: scope.ExePath, Harness: scope.Harness, Workspace: scope.Workspace})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range read() {
		if e.Observed.ID == recurring.ID && (!e.Expected || e.Candidate || e.ExpectedRuleID != exact.ID) {
			t.Fatalf("expected episode hidden or candidate: %+v", e)
		}
	}
	if err := st.RevokeExpectedEgressRule(exact.ID); err != nil {
		t.Fatal(err)
	}
	for _, e := range read() {
		if e.Observed.ID == recurring.ID && e.ExpectedRuleID != broad.ID {
			t.Fatalf("scope fallback=%+v", e)
		}
	}
}

func TestEgressEpisodesPrioritizesOlderCandidate(t *testing.T) {
	st := testStore(t)
	now := time.Now().UTC()
	scope := store.EgressScope{Agent: "claude", ExePath: "/usr/bin/claude", Harness: "claude", Workspace: "/work/a"}
	for i := 0; i < 5; i++ {
		if err := st.RecordEgressObservationForTest(store.EgressObservation{Scope: scope, Host: "203.0.113.1", Protocol: "tcp", Port: 443, At: now.Add(time.Duration(i-5) * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 101; i++ {
		if err := st.RecordEgressObservationForTest(store.EgressObservation{Scope: scope, Host: "198.51.100.1", Protocol: "tcp", Port: i + 1, At: now}); err != nil {
			t.Fatal(err)
		}
	}
	views := newTestAPI("", st, nil, nil).egressEpisodeViews()
	if len(views) != 101 || !views[0].Candidate || views[0].Observed.Host != "203.0.113.1" {
		t.Fatalf("older candidate not prioritized: count=%d first=%+v", len(views), views[0])
	}
}
