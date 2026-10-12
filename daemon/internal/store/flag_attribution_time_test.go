package store

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestReattributeFlagsHonorsNanosecondCutoff(t *testing.T) {
	for _, cutoff := range []string{
		"2026-10-11T12:00:00.123456789Z",
		"2026-10-11T13:00:00.123456789+01:00",
		"2026-10-11T12:00:00Z",
		"2026-10-11T12:00:00.999999999Z",
	} {
		t.Run(cutoff, func(t *testing.T) {
			s := labelStore(t)
			at, err := time.Parse(time.RFC3339Nano, cutoff)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range []struct {
				id, agent string
				pid       int32
				ts        time.Time
			}{
				{"before", "untagged:node", 42, at.Add(-time.Nanosecond)},
				{"at", "untagged:node", 42, at},
				{"after", "untagged:node", 42, at.Add(time.Nanosecond)},
				{"other-pid", "untagged:node", 43, at},
				{"tagged", "codex", 42, at},
			} {
				if _, err := s.PutFlag(model.Flag{ID: row.id, Rule: "keychain-access", Severity: 3, Agent: row.agent, PID: row.pid, TS: row.ts}); err != nil {
					t.Fatal(err)
				}
				stamp := row.ts.In(time.FixedZone("east", 5*60*60+45*60)).Format(time.RFC3339Nano)
				if _, err := s.db.Exec("UPDATE flags SET ts=? WHERE id=?", stamp, row.id); err != nil {
					t.Fatal(err)
				}
			}
			if n := s.ReattributeFlags(42, "claude", at); n != 2 {
				t.Fatalf("reattributed %d flags, want 2", n)
			}
			for id, agent := range map[string]string{"before": "untagged:node", "at": "claude", "after": "claude", "other-pid": "untagged:node", "tagged": "codex"} {
				f, found, err := s.GetFlagResult(id)
				if err != nil || !found || f.Agent != agent {
					t.Fatalf("flag %s: agent=%q found=%v err=%v, want %q", id, f.Agent, found, err, agent)
				}
			}
			if n := s.ReattributeFlags(42, "claude", at); n != 0 {
				t.Fatalf("second reattribution changed %d flags", n)
			}
		})
	}
}
