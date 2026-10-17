package api

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// A cached flag read follows every flag write: a new flag, an advisor verdict
// and an acknowledgement all show on the next read, and a caller changing its
// slice cannot change what the next caller gets.
func TestFlagReadCacheFollowsFlagWrites(t *testing.T) {
	a := explainTestAPI(t)
	now := time.Now()
	filter := store.FlagFilter{Rule: "keychain-access", Unacted: true, Since: dayWindow(now).UTC().Format(time.RFC3339), Limit: patternFlagLimit}
	read := func() []model.Flag {
		t.Helper()
		flags, err := a.flagReads.read(a.store, filter)
		if err != nil {
			t.Fatal(err)
		}
		return flags
	}
	a.store.PutFlag(keychainFlag("c1", "codex", 1, now, 2))
	got := read()
	if len(got) != 1 {
		t.Fatalf("first read: %+v", got)
	}
	got[0].ID = "changed"
	if again := read(); len(again) != 1 || again[0].ID != "c1" {
		t.Fatalf("a caller's slice reached the cache: %+v", again)
	}
	a.store.PutFlag(keychainFlag("c2", "codex", 1, now.Add(time.Second), 2))
	if got := read(); len(got) != 2 {
		t.Fatalf("new flag missing: %+v", got)
	}
	if err := a.store.PutAdvisorVerdict("c1", "flag", model.AdvisorVerdict{Rationale: "seen", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	for _, f := range read() {
		if f.ID == "c1" && (f.Advisor == nil || f.Advisor.Rationale != "seen") {
			t.Fatalf("verdict missing: %+v", f)
		}
	}
	a.store.AcknowledgeFlag("c2")
	if got := read(); len(got) != 1 || got[0].ID != "c1" {
		t.Fatalf("acknowledged flag still served: %+v", got)
	}
}

// Posture recomputed with no flag write in between, at 3000 flags in the
// window.
func BenchmarkComputePostureAtThreeThousandFlags(b *testing.B) {
	dir := b.TempDir()
	st, err := store.Open(filepath.Join(dir, "events.db"), "")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { st.Close() })
	a := newTestAPI(Deps{Store: st, Killer: &fakeKiller{}, Status: func() Status { return Status{Running: true} },
		Allowlist: correlate.NewAllowlistStore(filepath.Join(dir, "allowlist.json")),
		Mutes:     correlate.NewMuteStore(filepath.Join(dir, "mutes.json")), Guard: guard.NewBroker(time.Minute)})
	now := time.Now()
	for i := 0; i < 3000; i++ {
		f := keychainFlag(fmt.Sprintf("b%04d", i), fmt.Sprintf("agent%d", i%30), int32(1000+i%30), now.Add(-time.Duration(i)*time.Second), 2)
		if _, err := st.PutFlag(f); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.computePosture()
	}
}
