package store

import (
	"math"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestAdvisorPlanPersistenceFailureAndRecovery(t *testing.T) {
	for _, fault := range []string{"read-only", "zero-row", "serialization"} {
		t.Run(fault, func(t *testing.T) {
			s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			p := model.AdvisorPlan{Summary: "saved", EvidenceKey: "saved-key", CreatedAt: time.Now()}
			if err := s.PutAdvisorPlan("subject", p); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec("PRAGMA query_only = ON"); err != nil {
				t.Fatal(err)
			}
			s.PutAdvisorVerdict("other", "flag", model.AdvisorVerdict{Rationale: "other", CreatedAt: time.Now()})
			if fault != "read-only" {
				if _, err := s.db.Exec("PRAGMA query_only = OFF"); err != nil {
					t.Fatal(err)
				}
			}
			if fault == "zero-row" {
				if _, err := s.db.Exec(`CREATE TRIGGER skip_plan BEFORE INSERT ON advisor_plans BEGIN SELECT RAISE(IGNORE); END`); err != nil {
					t.Fatal(err)
				}
			}
			p.Summary, p.EvidenceKey = "new", "new-key"
			if fault == "serialization" {
				p.Confidence = math.Inf(1)
			}
			if err := s.PutAdvisorPlan("subject", p); err == nil {
				t.Fatal("failed plan reported persistence success")
			}
			if saved, ok := s.AdvisorPlanFor("subject"); !ok || saved.Summary != "saved" || saved.EvidenceKey != "saved-key" {
				t.Fatalf("failed save overwrote the previous plan: %+v, %v", saved, ok)
			}
			h := s.WriteHealth()
			if h.Failures != 2 || !slices.Equal(h.Active, []string{"advisor plans", "advisor verdicts"}) {
				t.Fatalf("plan persistence failure hidden: %+v", h)
			}
			if _, err := s.db.Exec("PRAGMA query_only = OFF"); err != nil {
				t.Fatal(err)
			}
			if fault == "zero-row" {
				if _, err := s.db.Exec("DROP TRIGGER skip_plan"); err != nil {
					t.Fatal(err)
				}
			}
			p.Confidence = 0.8
			if err := s.PutAdvisorPlan("subject", p); err != nil {
				t.Fatal(err)
			}
			if saved, ok := s.AdvisorPlanFor("subject"); !ok || saved.Summary != "new" || saved.EvidenceKey != "new-key" {
				t.Fatalf("plan did not recover: %+v, %v", saved, ok)
			}
			h = s.WriteHealth()
			if h.Failures != 2 || !slices.Equal(h.Active, []string{"advisor verdicts"}) {
				t.Fatalf("plan recovery erased another fault or failure history: %+v", h)
			}
		})
	}
}

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
