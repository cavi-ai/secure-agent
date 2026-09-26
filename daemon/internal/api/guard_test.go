package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// The advisor's recommendation is attached to /guard/pending once it lands,
// keyed by the same coordinates as the prompt. Advisory only: the prompt is
// still unresolved (the human decides).
func TestGuardPendingAttachesAdvisorAdvice(t *testing.T) {
	st := testStore(t)
	a := newTestAPI("", st, &fakeKiller{}, func() Status { return Status{Running: true} })
	a.guardBroker = newTestBroker()
	a.guardAdvisor = func(req model.GuardAssessmentRequest) {
		st.PutAdvisorVerdict(advisor.GuardSubjectID(req.Agent, req.RuleID, req.Path, req.Tool), "guard",
			model.AdvisorVerdict{Assessment: "malicious", Confidence: 0.9, Rationale: "exfiltration shape"})
	}
	// A blocked decision creates the pending prompt (and blocks; run async).
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/guard/decision",
			strings.NewReader(`{"agent":"claude","tool":"Read","path":"/x/.env","rule_id":"env-files"}`))
		a.handleGuardDecision(httptest.NewRecorder(), req)
	}()
	// Wait for the prompt to register, then read /guard/pending.
	deadline := time.Now().Add(2 * time.Second)
	var pending []guard.Pending
	for time.Now().Before(deadline) {
		rec := httptest.NewRecorder()
		a.handleGuardPending(rec, httptest.NewRequest(http.MethodGet, "/guard/pending", nil))
		if err := json.Unmarshal(rec.Body.Bytes(), &pending); err == nil && len(pending) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(pending) != 1 {
		t.Fatalf("pending = %d, want 1", len(pending))
	}
	if pending[0].Advisor == nil {
		t.Fatal("advisor advice not attached to the pending prompt")
	}
	if pending[0].Advisor.Assessment != "malicious" {
		t.Fatalf("advisor = %+v", pending[0].Advisor)
	}
	// The prompt is still pending — advice never resolves it.
	a.guardBroker.Resolve(pending[0].ID, guard.Decision{Verdict: "deny", Scope: "once"})
}

func TestGuardOutcomePersistence(t *testing.T) {
	cases := []struct{ name, setup, verdict, scope string }{
		{"cached", "cached", "deny", "always"},
		{"per-path", "path", "allow", "always"},
		{"operator", "operator", "allow", "once"},
		{"timeout", "timeout", "deny", "once"},
		{"queue-full", "full", "deny", "once"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := testStore(t)
			now := time.Now()
			st.UpsertSession(model.Session{ID: "session-1", Harness: "claude", StartedAt: now, LastSeenAt: now})
			a := newTestAPI("", st, &fakeKiller{}, func() Status { return Status{Running: true} })
			brokerTimeout := 25 * time.Millisecond
			if tc.setup == "full" {
				brokerTimeout = time.Second
			}
			a.guardBroker = guard.NewBroker(brokerTimeout)
			if tc.setup == "cached" {
				st.PutGuardRule(store.GuardRule{Agent: "claude", RuleID: "cloud-creds", Decision: "deny"})
			}
			if tc.setup == "path" {
				st.PutGuardPathAllow(store.GuardPathAllow{Agent: "claude", RuleID: "cloud-creds", Path: "/secret"})
			}
			if tc.setup == "full" {
				for i := 0; i < guard.MaxWaiters; i++ {
					p := guard.Pending{ID: fmt.Sprintf("fill-%d", i), Agent: "claude", RuleID: "rule", Path: fmt.Sprintf("/p-%d", i)}
					go a.guardBroker.Request(p)
				}
				deadline := time.Now().Add(time.Second)
				for len(a.guardBroker.Pending()) < guard.MaxWaiters && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				if len(a.guardBroker.Pending()) != guard.MaxWaiters {
					t.Fatal("queue did not fill")
				}
			}
			rec := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				req := httptest.NewRequest(http.MethodPost, "/guard/decision", strings.NewReader(`{"agent":"claude","tool":"Read","path":"/secret","rule_id":"cloud-creds","session_id":"session-1"}`))
				a.handleGuardDecision(rec, req)
				close(done)
			}()
			if tc.setup == "operator" {
				deadline := time.Now().Add(time.Second)
				for len(a.guardBroker.Pending()) == 0 && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				pending := a.guardBroker.Pending()
				if len(pending) != 1 {
					t.Fatal("prompt did not queue")
				}
				a.guardBroker.Resolve(pending[0].ID, guard.Decision{Verdict: "allow", Scope: "once"})
			}
			<-done
			if rec.Code != http.StatusOK {
				t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
			}
			rows := st.ListGuardDecisions("session-1", 10)
			if len(rows) != 1 {
				t.Fatalf("rows=%+v, want one", rows)
			}
			row := rows[0]
			if row.SessionID != "session-1" || row.RuleID != "cloud-creds" || row.Verdict != tc.verdict || row.Scope != tc.scope || row.ID == "" || row.At == "" {
				t.Fatalf("row=%+v", row)
			}
			encoded, _ := json.Marshal(row)
			if strings.Contains(string(encoded), "/secret") {
				t.Fatalf("path leaked: %s", encoded)
			}
		})
	}
}

func TestUnknownGuardSessionUnattributed(t *testing.T) {
	st := testStore(t)
	a := newTestAPI("", st, &fakeKiller{}, func() Status { return Status{Running: true} })
	a.guardBroker = guard.NewBroker(time.Millisecond)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/guard/decision", strings.NewReader(`{"agent":"claude","tool":"Read","path":"/secret","rule_id":"cloud-creds","session_id":"unknown"}`))
	a.handleGuardDecision(rec, req)
	var decision guard.Decision
	if err := json.Unmarshal(rec.Body.Bytes(), &decision); err != nil {
		t.Fatal(err)
	}
	if decision.Verdict != "deny" {
		t.Fatalf("decision=%+v", decision)
	}
	rows := st.ListGuardDecisions("", 10)
	if len(rows) != 1 || rows[0].SessionID != "" {
		t.Fatalf("rows=%+v", rows)
	}
}
