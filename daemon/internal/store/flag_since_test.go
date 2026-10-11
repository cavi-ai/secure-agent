package store

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestFlagSinceUsesInclusiveNanosecondCutoff(t *testing.T) {
	for _, cutoff := range []string{
		"2026-10-11T12:00:00.123456789Z",
		"2026-10-11T13:00:00.123456789+01:00",
		"2026-10-11T12:00:00Z",
		"2026-10-11T12:00:00.999999999Z",
		"2026-10-11T12:00:01Z",
	} {
		t.Run(cutoff, func(t *testing.T) {
			s, err := Open("", "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			at, err := time.Parse(time.RFC3339Nano, cutoff)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range []struct {
				id string
				ts time.Time
			}{{"before", at.Add(-time.Nanosecond)}, {"at", at}, {"after", at.Add(time.Nanosecond)}} {
				if _, err := s.PutFlag(model.Flag{ID: row.id, Rule: "rule", Agent: "codex", SessionID: "owned", Severity: 3, TS: row.ts}); err != nil {
					t.Fatal(err)
				}
				// Exercise historical offsets in storage as well as in the cutoff.
				stamp := row.ts.In(time.FixedZone("west", -4*60*60)).Format(time.RFC3339Nano)
				if _, err := s.db.Exec("UPDATE flags SET ts=? WHERE id=?", stamp, row.id); err != nil {
					t.Fatal(err)
				}
			}
			check := func(filter FlagFilter) {
				t.Helper()
				got, err := s.QueryFlagsResult(filter)
				var ids []string
				for _, flag := range got {
					ids = append(ids, flag.ID)
				}
				if err != nil || !slices.Equal(ids, []string{"after", "at"}) {
					t.Fatalf("inclusive cutoff %+v: ids=%v err=%v", filter, ids, err)
				}
			}
			check(FlagFilter{Since: cutoff, Limit: 10})
			if _, err := s.PutFlag(model.Flag{ID: "unrelated", Rule: "other", Agent: "other", SessionID: "other", Severity: 3, TS: at.Add(2 * time.Nanosecond)}); err != nil {
				t.Fatal(err)
			}
			check(FlagFilter{Agent: "codex", Rule: "rule", SessionID: "owned", MinSeverity: 3, Since: cutoff, Unacted: true, Limit: 10})
			q, args := flagQuery(FlagFilter{Since: cutoff, Limit: 10})
			if plan := queryPlan(t, s, q, args...); !strings.Contains(plan, "SEARCH flags USING INDEX idx_flags_instant_time") || strings.Contains(plan, "TEMP B-TREE") {
				t.Fatalf("cutoff does not seek the time index: %s", plan)
			}
		})
	}
}
