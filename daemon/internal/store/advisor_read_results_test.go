package store

import (
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestAdvisorReadRejectsCorruptionAndRecovers(t *testing.T) {
	for _, damage := range []string{"confidence='invalid'", "confidence=1e999", "created_at='invalid'", "rationale=NULL"} {
		t.Run(damage, func(t *testing.T) {
			s := reviewStore(t)
			v := model.AdvisorVerdict{Rationale: "stored", Confidence: .8, CreatedAt: time.Now().UTC()}
			if err := s.PutAdvisorVerdict("subject", "flag", v); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec("UPDATE advisor_verdicts SET " + damage); err != nil {
				t.Fatal(err)
			}
			if got, found := s.AdvisorVerdictFor("subject", "flag"); found || got != (model.AdvisorVerdict{}) {
				t.Errorf("corrupt verdict accepted: %+v %v", got, found)
			}
			if h := s.WriteHealth(); h.ReadFailures != 1 || !slices.Equal(h.ReadActive, []string{"flag advisor verdicts"}) {
				t.Errorf("advisor read failure hidden: %+v", h)
			}
			if err := s.PutAdvisorVerdict("subject", "flag", v); err != nil {
				t.Fatal(err)
			}
			if got, found := s.AdvisorVerdictFor("subject", "flag"); !found || !got.CreatedAt.Equal(v.CreatedAt) || got.Rationale != v.Rationale {
				t.Errorf("verdict recovery: %+v %v", got, found)
			}
			if h := s.WriteHealth(); h.ReadFailures != 1 || len(h.ReadActive) != 0 {
				t.Errorf("read recovery lost failure history: %+v", h)
			}
		})
	}
}

func TestAdvisorCheckedReadMissingUnavailableAndLegacyFields(t *testing.T) {
	s := reviewStore(t)
	if _, err := s.db.Exec("ALTER TABLE advisor_verdicts RENAME TO unavailable_advice"); err != nil {
		t.Fatal(err)
	}
	if v, found, err := s.AdvisorVerdictResultFor("missing", "flag"); err == nil || found || v != (model.AdvisorVerdict{}) {
		t.Errorf("unavailable advice treated as missing: %+v %v %v", v, found, err)
	}
	if _, err := s.db.Exec("ALTER TABLE unavailable_advice RENAME TO advisor_verdicts"); err != nil {
		t.Fatal(err)
	}
	if v, found, err := s.AdvisorVerdictResultFor("missing", "flag"); err != nil || found || v != (model.AdvisorVerdict{}) {
		t.Errorf("healthy missing advice: %+v %v %v", v, found, err)
	}
	if h := s.WriteHealth(); h.ReadFailures != 1 || len(h.ReadActive) != 0 {
		t.Errorf("missing-row recovery: %+v", h)
	}
	if err := s.PutAdvisorVerdict("legacy", "flag", model.AdvisorVerdict{Rationale: "stored", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE advisor_verdicts SET confidence=NULL,assessment=NULL,suggested_action=NULL,model=NULL,created_at=NULL"); err != nil {
		t.Fatal(err)
	}
	if v, found, err := s.AdvisorVerdictResultFor("legacy", "flag"); err != nil || !found || v.Rationale != "stored" || !v.CreatedAt.IsZero() {
		t.Errorf("supported null fields rejected: %+v %v %v", v, found, err)
	}
}

func TestIncidentAdvisorEnrichmentRetainsReportsAndReadFailure(t *testing.T) {
	s := reviewStore(t)
	now := time.Now().UTC()
	for i, id := range []string{"bad-incident-advisor", "good-incident-advisor"} {
		if err := s.PutIncident(model.IncidentReport{ID: id, Timestamp: now.Add(-time.Duration(i) * time.Minute)}); err != nil {
			t.Fatal(err)
		}
		if err := s.PutAdvisorVerdict(id, "incident", model.AdvisorVerdict{Rationale: "stored", CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec("UPDATE advisor_verdicts SET created_at='invalid' WHERE subject_id='bad-incident-advisor'"); err != nil {
		t.Fatal(err)
	}
	list, err := s.RecentIncidentsResult(10)
	if err != nil || len(list) != 2 {
		t.Fatalf("advice failure erased reports: %+v %v", list, err)
	}
	if list[0].ID != "bad-incident-advisor" || list[0].AdvisorNarrative != "" || list[1].AdvisorNarrative != "stored" {
		t.Errorf("invalid narrative or valid sibling lost: %+v", list)
	}
	if h := s.WriteHealth(); h.ReadFailures != 1 || !slices.Equal(h.ReadActive, []string{"incident advisor verdicts"}) {
		t.Errorf("healthy sibling hid failed narrative: %+v", h)
	}
	if report, err := s.GetIncident("bad-incident-advisor"); err != nil || report == nil || report.ID != "bad-incident-advisor" || report.AdvisorNarrative != "" {
		t.Errorf("detail lost core report: %+v %v", report, err)
	}
	if err := s.PutAdvisorVerdict("bad-incident-advisor", "incident", model.AdvisorVerdict{Rationale: "repaired", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecentIncidentsResult(10); err != nil {
		t.Fatal(err)
	}
	if h := s.WriteHealth(); h.ReadFailures != 2 || len(h.ReadActive) != 0 {
		t.Errorf("narrative recovery: %+v", h)
	}
}

func TestAdvisorEnrichmentRetainsCoreFindingsAndBatchFailure(t *testing.T) {
	s := reviewStore(t)
	now := time.Now().UTC()
	for i, id := range []string{"bad-advisor", "good-advisor"} {
		if _, err := s.PutFlag(model.Flag{ID: id, Rule: "keychain-access", Severity: 3, PID: 42, TS: now.Add(-time.Duration(i) * time.Minute)}); err != nil {
			t.Fatal(err)
		}
		if err := s.PutAdvisorVerdict(id, "flag", model.AdvisorVerdict{Rationale: "stored", CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec("UPDATE advisor_verdicts SET created_at='invalid' WHERE subject_id='bad-advisor'"); err != nil {
		t.Fatal(err)
	}
	flags, err := s.QueryFlagsResult(FlagFilter{})
	if err != nil || len(flags) != 2 {
		t.Fatalf("optional enrichment erased core findings: %+v %v", flags, err)
	}
	if flags[0].ID != "bad-advisor" || flags[0].Advisor != nil || flags[1].Advisor == nil {
		t.Errorf("invalid enrichment or valid sibling lost: %+v", flags)
	}
	if _, found := s.AdvisorVerdictFor("missing", "incident"); found {
		t.Fatal("missing incident verdict reported present")
	}
	if h := s.WriteHealth(); h.ReadFailures != 1 || !slices.Equal(h.ReadActive, []string{"flag advisor verdicts"}) {
		t.Errorf("later healthy sibling or different kind hid failure: %+v", h)
	}
	if err := s.PutAdvisorVerdict("bad-advisor", "flag", model.AdvisorVerdict{Rationale: "repaired", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if flags, err := s.QueryFlagsResult(FlagFilter{}); err != nil || len(flags) != 2 || flags[0].Advisor == nil {
		t.Errorf("batch recovery: %+v %v", flags, err)
	}
	if h := s.WriteHealth(); h.ReadFailures != 1 || len(h.ReadActive) != 0 {
		t.Errorf("batch recovery lost failure history: %+v", h)
	}
}
