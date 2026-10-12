package store

import (
	"github.com/cavi-ai/secure-agent/daemon/internal/testutil"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestBumpFlagRepeat(t *testing.T) {
	s := labelStore(t)
	base := time.Date(2026, 9, 25, 20, 0, 0, 0, time.UTC)
	s.PutFlag(model.Flag{ID: "f1", Rule: "sensitive-read-then-connect", Severity: 3, TS: base, Agent: "claude"})
	if s.BumpFlagRepeat("missing", base) {
		t.Fatal("bump of an unknown flag reported success")
	}
	if f, _ := testutil.Lookup[model.Flag](t)(s.GetFlagResult("f1")); f.Repeats != 0 || f.LastSeen != nil {
		t.Fatalf("fresh flag repeats/last_seen = %d/%v, want 0/nil", f.Repeats, f.LastSeen)
	}
	later := base.Add(5 * time.Minute)
	for _, at := range []time.Time{later, base.Add(time.Minute)} {
		if !s.BumpFlagRepeat("f1", at) {
			t.Fatal("bump failed")
		}
	}
	f, _ := testutil.Lookup[model.Flag](t)(s.GetFlagResult("f1"))
	if f.Repeats != 2 || f.LastSeen == nil || !f.LastSeen.Equal(later) {
		t.Fatalf("repeats/last_seen = %d/%v, want 2/%v (an older repeat never moves it back)", f.Repeats, f.LastSeen, later)
	}
	q := testutil.Read[[]model.Flag](t)(s.QueryFlagsResult(FlagFilter{Rule: "sensitive-read-then-connect"}))
	if len(q) != 1 || q[0].Repeats != 2 || q[0].LastSeen == nil {
		t.Fatalf("QueryFlags = %+v, want the repeats carried", q)
	}
}

func TestBumpFlagRepeatPreservesNewestNanosecond(t *testing.T) {
	for _, tc := range []struct {
		name, older, newer string
	}{
		{"nanoseconds", "2026-10-11T12:00:00.123456788Z", "2026-10-11T12:00:00.123456789Z"},
		{"fraction widths", "2026-10-11T12:00:00.1Z", "2026-10-11T12:00:00.100000001Z"},
		{"whole second", "2026-10-11T12:00:00Z", "2026-10-11T12:00:00.000000001Z"},
		{"second boundary", "2026-10-11T12:00:00.999999999Z", "2026-10-11T12:00:01Z"},
		{"stored offset", "2026-10-11T17:45:00.123456788+05:45", "2026-10-11T12:00:00.123456789Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := labelStore(t)
			older, err := time.Parse(time.RFC3339Nano, tc.older)
			if err != nil {
				t.Fatal(err)
			}
			newer, err := time.Parse(time.RFC3339Nano, tc.newer)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.PutFlag(model.Flag{ID: "f", Rule: "sensitive-read-then-connect", Agent: "claude", Severity: 3, TS: older}); err != nil {
				t.Fatal(err)
			}
			if !s.BumpFlagRepeat("f", older) {
				t.Fatal("initial repeat failed")
			}
			// Preserve historical offset and fractional-width representations.
			if _, err := s.db.Exec("UPDATE flags SET last_seen=? WHERE id='f'", tc.older); err != nil {
				t.Fatal(err)
			}
			for i, at := range []time.Time{newer, older, newer.In(time.FixedZone("west", -4*60*60))} {
				if !s.BumpFlagRepeat("f", at) {
					t.Fatal("repeat failed")
				}
				f, found, err := s.GetFlagResult("f")
				if err != nil || !found || f.Repeats != i+2 || f.LastSeen == nil || !f.LastSeen.Equal(newer) {
					t.Fatalf("repeat %d: flag=%+v found=%v err=%v, want repeats=%d last_seen=%s", i, f, found, err, i+2, newer)
				}
			}
			flags, err := s.QueryFlagsResult(FlagFilter{Rule: "sensitive-read-then-connect"})
			if err != nil || len(flags) != 1 || flags[0].Repeats != 4 || flags[0].LastSeen == nil || !flags[0].LastSeen.Equal(newer) {
				t.Fatalf("history: flags=%+v err=%v", flags, err)
			}
		})
	}
}
