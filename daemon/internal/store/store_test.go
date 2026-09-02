package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestPutAndReadFlagRoundTrips(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), filepath.Join(dir, "e.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.PutFlag(model.Flag{ID: "f1", Rule: "r", Severity: 3, PID: 7, Agent: "cursor"})
	got := s.RecentFlags(10)
	if len(got) != 1 || got[0].ID != "f1" {
		t.Fatalf("RecentFlags = %+v", got)
	}
}

func TestPutFlagAlsoAppendsJSONL(t *testing.T) {
	dir := t.TempDir()
	jl := filepath.Join(dir, "e.jsonl")
	s, _ := Open(filepath.Join(dir, "e.db"), jl)
	s.PutFlag(model.Flag{ID: "f1", Rule: "r", Severity: 1})
	s.Close()
	b, _ := os.ReadFile(jl)
	if !strings.Contains(string(b), `"f1"`) {
		t.Fatal("flag not mirrored to JSONL")
	}
}

func TestPutAndReadAuditRoundTrips(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.PutAudit(AuditEntry{Action: "rule-mode", Rule: "aws-key", FromMode: "monitor", ToMode: "block"})
	got := s.RecentAudit(10)
	if len(got) != 1 {
		t.Fatalf("RecentAudit len = %d, want 1", len(got))
	}
	a := got[0]
	if a.Action != "rule-mode" || a.Rule != "aws-key" || a.FromMode != "monitor" || a.ToMode != "block" {
		t.Fatalf("audit row = %+v", a)
	}
	if a.ID == 0 || a.TS == "" {
		t.Fatalf("audit row missing stamped id/ts: %+v", a)
	}
}

func TestQueryFlagsFilters(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	base := time.Now()
	s.PutFlag(model.Flag{ID: "a", Rule: "proxy-secret-leak", Severity: 3, Agent: "claude", PID: 1, TS: base})
	s.PutFlag(model.Flag{ID: "b", Rule: "keychain-access", Severity: 1, Agent: "cursor", PID: 2, TS: base})
	s.PutFlag(model.Flag{ID: "c", Rule: "proxy-secret-leak", Severity: 2, Agent: "cursor", PID: 3, TS: base})

	cases := []struct {
		name string
		f    FlagFilter
		want int
	}{
		{"agent", FlagFilter{Agent: "cursor"}, 2},
		{"rule", FlagFilter{Rule: "proxy-secret-leak"}, 2},
		{"min_severity", FlagFilter{MinSeverity: 2}, 2},
		{"combined", FlagFilter{Agent: "cursor", Rule: "proxy-secret-leak", MinSeverity: 2}, 1},
		{"none", FlagFilter{}, 3},
	}
	for _, tc := range cases {
		if got := s.QueryFlags(tc.f); len(got) != tc.want {
			t.Errorf("%s: got %d flags, want %d", tc.name, len(got), tc.want)
		}
	}
}

// TestQueryFlagsSinceNormalizesTimezone pins the datetime() comparison: a flag
// stamped with a non-UTC offset must be matched correctly against a UTC `since`.
// A raw string comparison (10:00-04:00 vs 13:00Z) would wrongly exclude it.
func TestQueryFlagsSinceNormalizesTimezone(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	edt := time.FixedZone("EDT", -4*3600)
	s.PutFlag(model.Flag{ID: "x", Rule: "r", Severity: 1, Agent: "claude", PID: 1,
		TS: time.Date(2026, 8, 31, 10, 0, 0, 0, edt)}) // == 14:00Z

	if got := s.QueryFlags(FlagFilter{Since: "2026-08-31T13:00:00Z"}); len(got) != 1 {
		t.Fatalf("since=13:00Z should include a 14:00Z flag, got %d", len(got))
	}
	if got := s.QueryFlags(FlagFilter{Since: "2026-08-31T15:00:00Z"}); len(got) != 0 {
		t.Fatalf("since=15:00Z should exclude a 14:00Z flag, got %d", len(got))
	}
}

func TestQueryEventsFilters(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now()
	s.PutEvent(event.Event{Kind: event.KindFileOpen, PID: 10, TS: now})
	s.PutEvent(event.Event{Kind: event.KindProxyHit, PID: 20, TS: now})
	s.PutEvent(event.Event{Kind: event.KindFileOpen, PID: 20, TS: now})

	fileOpen := int(event.KindFileOpen)
	if got := s.QueryEvents(EventFilter{Kind: &fileOpen}); len(got) != 2 {
		t.Errorf("kind=FileOpen (0) got %d, want 2", len(got))
	}
	if got := s.QueryEvents(EventFilter{PID: 20}); len(got) != 2 {
		t.Errorf("pid=20 got %d, want 2", len(got))
	}
	if got := s.QueryEvents(EventFilter{Kind: &fileOpen, PID: 20}); len(got) != 1 {
		t.Errorf("kind=FileOpen pid=20 got %d, want 1", len(got))
	}
	if got := s.QueryEvents(EventFilter{}); len(got) != 3 {
		t.Errorf("no filter got %d, want 3", len(got))
	}
}

func TestEventRetentionBatchPruning(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	for i := 0; i < 2500; i++ {
		s.PutEvent(event.Event{Kind: event.KindExec, PID: int32(i)})
	}

	s.PruneEvents(100)
	eventsAfterPrune := s.RecentEvents(2000)
	if len(eventsAfterPrune) != 100 {
		t.Fatalf("events count after explicit prune = %d, want 100", len(eventsAfterPrune))
	}
}

func TestGuardRuleRoundTrip(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if _, ok := s.LookupGuardRule("claude", "cloud-creds"); ok {
		t.Fatal("expected no rule before Put")
	}
	s.PutGuardRule(GuardRule{Agent: "claude", RuleID: "cloud-creds", Decision: "allow", Source: "prompt"})

	got, ok := s.LookupGuardRule("claude", "cloud-creds")
	if !ok || got.Decision != "allow" {
		t.Fatalf("lookup = %+v, ok=%v", got, ok)
	}
	// Per-agent scope: cursor is unaffected.
	if _, ok := s.LookupGuardRule("cursor", "cloud-creds"); ok {
		t.Fatal("rule leaked across agents")
	}
	// Upsert: a second Put replaces the decision, not duplicates it.
	s.PutGuardRule(GuardRule{Agent: "claude", RuleID: "cloud-creds", Decision: "deny", Source: "prompt"})
	got, _ = s.LookupGuardRule("claude", "cloud-creds")
	if got.Decision != "deny" {
		t.Fatalf("upsert failed, decision=%q", got.Decision)
	}
	if n := len(s.ListGuardRules(0)); n != 1 {
		t.Fatalf("ListGuardRules = %d rows, want 1", n)
	}
	if !s.DeleteGuardRule("claude", "cloud-creds") {
		t.Fatal("delete returned false")
	}
	if _, ok := s.LookupGuardRule("claude", "cloud-creds"); ok {
		t.Fatal("rule survived delete")
	}
}

func TestListGuardRulesEmptyIsEmptyArrayNotNull(t *testing.T) {
	// A nil []GuardRule marshals to JSON `null`, not `[]`; a menubar/dashboard
	// client expecting an array to iterate over should never see null.
	s, err := Open("", "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	rules := s.ListGuardRules(10)
	if rules == nil {
		t.Fatal("ListGuardRules returned nil, want a non-nil empty slice")
	}
	b, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != "[]" {
		t.Fatalf("json = %s, want []", b)
	}
}
