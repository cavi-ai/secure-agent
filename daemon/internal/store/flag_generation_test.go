package store

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestFlagWritesAdvanceTheGeneration(t *testing.T) {
	s := reviewStore(t)
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	step := func(name string, write func() bool) {
		t.Helper()
		before := s.FlagGeneration()
		changed := write()
		if after := s.FlagGeneration(); (after != before) != changed {
			t.Errorf("%s: generation %d -> %d, write changed rows %v", name, before, after, changed)
		}
	}
	step("put", func() bool {
		r, err := s.PutFlag(model.Flag{ID: "g1", Rule: "r", Severity: 2, PID: 7, Agent: "untagged:7", TS: at})
		return err == nil && r.Changed
	})
	step("repeat", func() bool { return s.BumpFlagRepeat("g1", at.Add(time.Minute)) })
	step("reattribute", func() bool { return s.ReattributeFlags(7, "claude", at.Add(-time.Hour)) > 0 })
	step("verdict", func() bool {
		return s.PutAdvisorVerdict("g1", "flag", model.AdvisorVerdict{Rationale: "r", CreatedAt: at}) == nil
	})
	step("acknowledge", func() bool { return s.AcknowledgeFlag("g1") })
	step("acknowledge missing", func() bool { return s.AcknowledgeFlag("missing") })
	step("reattribute nothing", func() bool { return s.ReattributeFlags(99, "claude", at) > 0 })
}
