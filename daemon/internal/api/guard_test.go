package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
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
