package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestAdvisorPlanRoundTripAndReplace(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, ok := s.AdvisorPlanFor("file:/w/a"); ok {
		t.Fatal("unknown subject must not have a plan")
	}
	p := model.AdvisorPlan{Summary: "first", Why: []string{"w"}, Risk: "high",
		Prevent: []model.PlanStep{{Kind: "guard-rule", Step: "s", Detail: "d"}}, Behavior: []string{}, Remediate: []string{"r"},
		Actions: []string{"dismiss"}, Confidence: 0.8, Model: "m", CreatedAt: time.Now().UTC().Truncate(time.Second), EvidenceKey: "k1"}
	s.PutAdvisorPlan("file:/w/a", p)
	got, ok := s.AdvisorPlanFor("file:/w/a")
	if !ok || got.Summary != "first" || got.EvidenceKey != "k1" || got.Prevent[0].Kind != "guard-rule" || !got.CreatedAt.Equal(p.CreatedAt) {
		t.Fatalf("round trip = %+v ok=%v", got, ok)
	}
	p.Summary, p.EvidenceKey = "second", "k2"
	s.PutAdvisorPlan("file:/w/a", p)
	if got, _ := s.AdvisorPlanFor("file:/w/a"); got.Summary != "second" || got.EvidenceKey != "k2" {
		t.Fatalf("replace = %+v", got)
	}
}
