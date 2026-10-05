package store

import (
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestAdvisorVerdictWriteFailureRecoversIndependently(t *testing.T) {
	for _, fault := range []string{"read-only", "zero-row"} {
		t.Run(fault, func(t *testing.T) {
			s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			verdict := model.AdvisorVerdict{Rationale: "saved", CreatedAt: time.Now()}
			if err := s.PutAdvisorVerdict("subject", "flag", verdict); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec("PRAGMA query_only = ON"); err != nil {
				t.Fatal(err)
			}
			s.PutEvent(event.Event{Kind: event.KindPluginAction, TS: time.Now()})
			if fault == "zero-row" {
				if _, err := s.db.Exec("PRAGMA query_only = OFF"); err != nil {
					t.Fatal(err)
				}
				if _, err := s.db.Exec(`CREATE TRIGGER skip_verdict BEFORE INSERT ON advisor_verdicts BEGIN SELECT RAISE(IGNORE); END`); err != nil {
					t.Fatal(err)
				}
			}
			verdict.Rationale = "new"
			if err := s.PutAdvisorVerdict("subject", "flag", verdict); err == nil {
				t.Fatal("failed write reported verdict persistence success")
			}
			if got, ok := s.AdvisorVerdictFor("subject", "flag"); !ok || got.Rationale != "saved" {
				t.Fatalf("failed write changed saved verdict: %+v, %v", got, ok)
			}
			h := s.WriteHealth()
			if h.Failures != 2 || !slices.Equal(h.Active, []string{"advisor verdicts", "events"}) {
				t.Fatalf("advisor persistence fault hidden: %+v", h)
			}
			if _, err := s.db.Exec("PRAGMA query_only = OFF"); err != nil {
				t.Fatal(err)
			}
			if fault == "zero-row" {
				if _, err := s.db.Exec("DROP TRIGGER skip_verdict"); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.PutAdvisorVerdict("subject", "flag", verdict); err != nil {
				t.Fatal(err)
			}
			if got, ok := s.AdvisorVerdictFor("subject", "flag"); !ok || got.Rationale != "new" {
				t.Fatalf("recovered verdict was not saved: %+v, %v", got, ok)
			}
			h = s.WriteHealth()
			if h.Failures != 2 || !slices.Equal(h.Active, []string{"events"}) {
				t.Fatalf("verdict recovery erased another fault or failure history: %+v", h)
			}
		})
	}
}
