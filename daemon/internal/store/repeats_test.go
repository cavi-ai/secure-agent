package store

import (
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
	if f, _ := s.GetFlag("f1"); f.Repeats != 0 || f.LastSeen != nil {
		t.Fatalf("fresh flag repeats/last_seen = %d/%v, want 0/nil", f.Repeats, f.LastSeen)
	}
	later := base.Add(5 * time.Minute)
	for _, at := range []time.Time{later, base.Add(time.Minute)} {
		if !s.BumpFlagRepeat("f1", at) {
			t.Fatal("bump failed")
		}
	}
	f, _ := s.GetFlag("f1")
	if f.Repeats != 2 || f.LastSeen == nil || !f.LastSeen.Equal(later) {
		t.Fatalf("repeats/last_seen = %d/%v, want 2/%v (an older repeat never moves it back)", f.Repeats, f.LastSeen, later)
	}
	q := s.QueryFlags(FlagFilter{Rule: "sensitive-read-then-connect"})
	if len(q) != 1 || q[0].Repeats != 2 || q[0].LastSeen == nil {
		t.Fatalf("QueryFlags = %+v, want the repeats carried", q)
	}
}
