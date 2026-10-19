package store

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// Verdicts attach across query batches, and a corrupt row leaves the rest of
// its batch attached.
func TestQueryFlagsAttachesVerdictsAcrossBatches(t *testing.T) {
	s := reviewStore(t)
	n := 2*advisorVerdictBatch + 7
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("f-%d", i)
		if _, err := s.db.Exec(`INSERT INTO flags (id, rule, severity, ts, pid, agent) VALUES (?, 'r', 2, ?, ?, 'claude')`,
			id, base.Add(time.Duration(i)*time.Second).Format(time.RFC3339Nano), i); err != nil {
			t.Fatal(err)
		}
		if i%3 != 0 {
			if err := s.PutAdvisorVerdict(id, "flag", model.AdvisorVerdict{Rationale: id, CreatedAt: base}); err != nil {
				t.Fatal(err)
			}
		}
	}
	corrupt := fmt.Sprintf("f-%d", advisorVerdictBatch+2) // in the second batch, with a verdict
	if _, err := s.db.Exec(`UPDATE advisor_verdicts SET created_at='invalid' WHERE subject_id=?`, corrupt); err != nil {
		t.Fatal(err)
	}
	flags, err := s.QueryFlags(FlagFilter{Limit: n})
	if err != nil || len(flags) != n {
		t.Fatalf("flags: %d %v", len(flags), err)
	}
	for _, f := range flags {
		var i int
		if _, err := fmt.Sscanf(f.ID, "f-%d", &i); err != nil {
			t.Fatal(err)
		}
		want := i%3 != 0 && f.ID != corrupt
		if (f.Advisor != nil) != want || want && f.Advisor.Rationale != f.ID {
			t.Errorf("%s advisor = %+v, want attached %v", f.ID, f.Advisor, want)
		}
	}
	if h := s.WriteHealth(); !slices.Equal(h.ReadActive, []string{"flag advisor verdicts"}) {
		t.Errorf("corrupt verdict not reported: %+v", h)
	}
}

func TestAdvisorVerdictBatchRetainsFailuresAndValidSiblings(t *testing.T) {
	for _, ids := range [][]string{{"bad", "good", "missing", "bad"}, {"good", "bad", "missing", "bad"}} {
		t.Run(ids[0], func(t *testing.T) {
			s := reviewStore(t)
			for _, id := range []string{"bad", "good"} {
				if err := s.PutAdvisorVerdict(id, "host", model.AdvisorVerdict{Rationale: "stored", CreatedAt: time.Now().UTC()}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.db.Exec(`UPDATE advisor_verdicts SET created_at='invalid' WHERE subject_id='bad'`); err != nil {
				t.Fatal(err)
			}
			got, err := s.AdvisorVerdictsFor(ids, "host")
			if err == nil || len(got) != 1 || got["good"].Rationale != "stored" {
				t.Errorf("corrupt or valid batch result: %+v %v", got, err)
			}
			if h := s.WriteHealth(); h.ReadFailures != 1 || !slices.Equal(h.ReadActive, []string{"host advisor verdicts"}) {
				t.Errorf("later sibling hid batch failure: %+v", h)
			}
			// Nullable legacy metadata is still supported by the shared decoder.
			if _, err := s.db.Exec(`UPDATE advisor_verdicts SET created_at=NULL,confidence=NULL,assessment=NULL,suggested_action=NULL,model=NULL WHERE kind='host'`); err != nil {
				t.Fatal(err)
			}
			got, err = s.AdvisorVerdictsFor(ids, "host")
			if err != nil || len(got) != 2 || got["bad"].Rationale != "stored" || !got["bad"].CreatedAt.IsZero() || got["bad"].Confidence != 0 {
				t.Errorf("legacy repair: %+v %v", got, err)
			}
			if h := s.WriteHealth(); h.ReadFailures != 1 || len(h.ReadActive) != 0 {
				t.Errorf("repair lost failure history: %+v", h)
			}
		})
	}
}

func TestAdvisorVerdictBatchKeepsIndependentReadKinds(t *testing.T) {
	s := reviewStore(t)
	if err := s.PutAdvisorVerdict("flag", "flag", model.AdvisorVerdict{Rationale: "stored", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE advisor_verdicts SET created_at='invalid' WHERE kind='flag'`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AdvisorVerdictResultFor("flag", "flag"); err == nil {
		t.Fatal("fixture must fail the flag read")
	}
	for _, ids := range [][]string{{"missing"}, nil} {
		got, err := s.AdvisorVerdictsFor(ids, "host")
		if err != nil || len(got) != 0 {
			t.Errorf("healthy missing or empty host batch: %+v %v", got, err)
		}
		if h := s.WriteHealth(); h.ReadFailures != 1 || !slices.Equal(h.ReadActive, []string{"flag advisor verdicts"}) {
			t.Errorf("unrelated batch cleared the flag fault: %+v", h)
		}
	}
}
