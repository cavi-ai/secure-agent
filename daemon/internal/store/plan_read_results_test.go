package store

import (
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestPlanReadRejectsCorruptionAndRecovers(t *testing.T) {
	for _, damage := range []string{"plan_json='null'", "plan_json='{}'", "plan_json='invalid'", "created_at='invalid'", "created_at='2000-01-01T00:00:00Z'"} {
		t.Run(damage, func(t *testing.T) {
			s := reviewStore(t)
			p := model.AdvisorPlan{Summary: "stored", CreatedAt: time.Now().UTC(), EvidenceKey: "key"}
			if err := s.PutAdvisorPlan("subject", p); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec("UPDATE advisor_plans SET " + damage); err != nil {
				t.Fatal(err)
			}
			if got, found := s.AdvisorPlanFor("subject"); found || got.Summary != "" || got.EvidenceKey != "" || !got.CreatedAt.IsZero() {
				t.Errorf("corrupt plan accepted or partial payload returned: %+v %v", got, found)
			}
			if h := s.WriteHealth(); h.ReadFailures != 1 || !slices.Equal(h.ReadActive, []string{"advisor plans"}) {
				t.Errorf("plan read failure hidden: %+v", h)
			}
			if err := s.PutAdvisorPlan("subject", p); err != nil {
				t.Fatal(err)
			}
			if got, found := s.AdvisorPlanFor("subject"); !found || got.Summary != p.Summary || !got.CreatedAt.Equal(p.CreatedAt) {
				t.Errorf("plan recovery: %+v %v", got, found)
			}
			if h := s.WriteHealth(); h.ReadFailures != 1 || len(h.ReadActive) != 0 {
				t.Errorf("recovery lost read failure history: %+v", h)
			}
		})
	}
}

func TestCheckedPlanReadMissingUnavailableAndCompatibility(t *testing.T) {
	s := reviewStore(t)
	if _, err := s.db.Exec("ALTER TABLE advisor_plans RENAME TO unavailable_plans"); err != nil {
		t.Fatal(err)
	}
	if got, found, err := s.AdvisorPlanResultFor("missing"); err == nil || found || got.Summary != "" {
		t.Errorf("unavailable plan treated as missing: %+v %v %v", got, found, err)
	}
	if _, err := s.db.Exec("ALTER TABLE unavailable_plans RENAME TO advisor_plans"); err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.AdvisorPlanResultFor("missing"); err != nil || found {
		t.Errorf("healthy missing plan: %v %v", found, err)
	}
	if h := s.WriteHealth(); h.ReadFailures != 1 || len(h.ReadActive) != 0 {
		t.Errorf("missing-row recovery: %+v", h)
	}
	for _, at := range []time.Time{time.Time{}, time.Now().In(time.FixedZone("offset", 5*60*60))} {
		p := model.AdvisorPlan{Summary: "supported", CreatedAt: at}
		if err := s.PutAdvisorPlan("legacy", p); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec("UPDATE advisor_plans SET plan_json=json_set(plan_json,'$.future_field','supported')"); err != nil {
			t.Fatal(err)
		}
		if got, found, err := s.AdvisorPlanResultFor("legacy"); err != nil || !found || !got.CreatedAt.Equal(at) {
			t.Errorf("valid zero/offset timestamp rejected: %+v %v %v", got, found, err)
		}
		if _, err := s.db.Exec("UPDATE advisor_plans SET created_at=NULL"); err != nil {
			t.Fatal(err)
		}
		if got, found, err := s.AdvisorPlanResultFor("legacy"); err != nil || !found || got.Summary != p.Summary {
			t.Errorf("nullable legacy index timestamp rejected: %+v %v %v", got, found, err)
		}
	}
}
