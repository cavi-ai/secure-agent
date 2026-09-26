package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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

func TestPutFlagRotatesJSONLWhenOverCap(t *testing.T) {
	dir := t.TempDir()
	jl := filepath.Join(dir, "e.jsonl")
	prev := jsonlRotateBytes
	jsonlRotateBytes = 80
	t.Cleanup(func() { jsonlRotateBytes = prev })

	s, err := Open(filepath.Join(dir, "e.db"), jl)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := 0; i < 8; i++ {
		s.PutFlag(model.Flag{ID: fmt.Sprintf("flag-%d", i), Rule: "proxy-secret-leak", Severity: 3, Agent: "claude"})
	}
	rotated := jl + ".1"
	if _, err := os.Stat(rotated); err != nil {
		t.Fatalf("expected rotated file %s: %v", rotated, err)
	}
	cur, err := os.ReadFile(jl)
	if err != nil {
		t.Fatal(err)
	}
	if len(cur) == 0 {
		t.Fatal("active jsonl empty after rotate")
	}
	old, err := os.ReadFile(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if len(old) == 0 {
		t.Fatal("rotated jsonl empty")
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
		s.PutEvent(event.Event{Kind: event.KindExec, PID: int32(i), TS: time.Now()})
	}

	setKindBudget(t, int(event.KindExec), 100)
	s.PruneEvents()
	eventsAfterPrune := s.RecentEvents(2000)
	if len(eventsAfterPrune) != 100 {
		t.Fatalf("events count after explicit prune = %d, want 100", len(eventsAfterPrune))
	}
}

// Retention is time-based per kind: socket churn ages out in hours so it can
// never evict the security record again (the 10k-row, zero-activity window),
// while file/exec/guard kinds keep days.
func TestEventRetentionPerKindTimeWindows(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetEventRetention(24*time.Hour, 7*24*time.Hour)

	now := time.Now()
	put := func(kind event.Kind, age time.Duration) {
		s.PutEvent(event.Event{Kind: kind, PID: 42, TS: now.Add(-age)})
	}
	put(event.KindConnOpen, 48*time.Hour)      // stale churn: pruned
	put(event.KindConnClose, 48*time.Hour)     // stale churn: pruned
	put(event.KindConnOpen, time.Hour)         // fresh churn: kept
	put(event.KindExec, 48*time.Hour)          // 2d old, within 7d: kept
	put(event.KindFileOpen, 30*24*time.Hour)   // 30d old: pruned
	put(event.KindGuardPrompt, 6*24*time.Hour) // 6d old, within 7d: kept

	s.PruneEvents()

	got := map[event.Kind]int{}
	for _, e := range s.RecentEvents(100) {
		got[e.Kind]++
	}
	want := map[event.Kind]int{
		event.KindConnOpen:    1,
		event.KindConnClose:   0,
		event.KindExec:        1,
		event.KindFileOpen:    0,
		event.KindGuardPrompt: 1,
	}
	for kind, n := range want {
		if got[kind] != n {
			t.Errorf("kind %s: kept %d, want %d", kind, got[kind], n)
		}
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

func TestIncidentStatusWorkflowForwardOnly(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id := "inc-wf-1"
	s.PutIncident(model.IncidentReport{ID: id, Summary: "test", Risk: model.RiskHigh})

	if wf, ok := s.IncidentStatus(id); !ok || wf.Status != "open" {
		t.Fatalf("initial status = %+v ok=%v, want open", wf, ok)
	}

	if ok, err := s.SetIncidentStatus(id, "acknowledged", ""); err != nil || !ok {
		t.Fatalf("ack: ok=%v err=%v", ok, err)
	}
	wf, _ := s.IncidentStatus(id)
	if wf.Status != "acknowledged" || wf.AcknowledgedAt == "" {
		t.Fatalf("after ack = %+v", wf)
	}
	firstAck := wf.AcknowledgedAt

	// Re-ack keeps the first stamp.
	time.Sleep(10 * time.Millisecond)
	_, _ = s.SetIncidentStatus(id, "acknowledged", "")
	wf, _ = s.IncidentStatus(id)
	if wf.AcknowledgedAt != firstAck {
		t.Fatal("acknowledged_at must be stamped only once")
	}

	if ok, err := s.SetIncidentStatus(id, "resolved", "rotated keys"); err != nil || !ok {
		t.Fatalf("resolve: ok=%v err=%v", ok, err)
	}
	wf, _ = s.IncidentStatus(id)
	if wf.Status != "resolved" || wf.ResolvedAt == "" || wf.ResolutionNote != "rotated keys" {
		t.Fatalf("after resolve = %+v", wf)
	}

	// Unknown id must not be a silent success.
	if ok, _ := s.SetIncidentStatus("nope", "resolved", ""); ok {
		t.Fatal("unknown incident reported resolved")
	}
	if _, ok := s.IncidentStatus("nope"); ok {
		t.Fatal("unknown incident has status")
	}
}

func TestFlagSessionIDRoundTrips(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), filepath.Join(dir, "e.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.PutFlag(model.Flag{ID: "fs1", Rule: "sensitive-read-then-connect", Severity: 3,
		PID: 42, Agent: "claude", SessionID: "sess-abc-123", TS: time.Now().UTC()})
	flags := s.RecentFlags(10)
	if len(flags) != 1 {
		t.Fatalf("expected 1 flag, got %d", len(flags))
	}
	if flags[0].SessionID != "sess-abc-123" {
		t.Fatalf("session_id = %q, want sess-abc-123 (evidence chain must survive the store)", flags[0].SessionID)
	}
	// A flag without a session reads back empty, not an error.
	s.PutFlag(model.Flag{ID: "fs2", Rule: "r", Severity: 1, TS: time.Now().UTC()})
	if got := s.RecentFlags(10); len(got) != 2 {
		t.Fatalf("expected 2 flags, got %d", len(got))
	}
}

func TestCriticalFlagsMissingAdvisor(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "t.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	recent := time.Now().Add(-1 * time.Hour)
	old := time.Now().Add(-10 * 24 * time.Hour)
	st.PutFlag(model.Flag{ID: "f1", Rule: "r", Severity: 3, TS: recent, PID: 1})
	st.PutFlag(model.Flag{ID: "f2", Rule: "r", Severity: 2, TS: recent, PID: 1}) // below sev3
	st.PutFlag(model.Flag{ID: "f3", Rule: "r", Severity: 3, TS: old, PID: 1})    // outside window
	st.PutFlag(model.Flag{ID: "f4", Rule: "r", Severity: 3, TS: recent, PID: 1})
	// f4 already has a verdict — excluded.
	st.PutAdvisorVerdict("f4", "flag", model.AdvisorVerdict{Assessment: "benign", Rationale: "x"})

	got := st.CriticalFlagsMissingAdvisor(time.Now().Add(-7*24*time.Hour), 10)
	if len(got) != 1 || got[0].ID != "f1" {
		t.Fatalf("backfill set = %v, want [f1]", got)
	}
}

func TestLastEventTimes(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "t.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now()
	st.PutEvent(event.Event{Kind: event.KindFileOpen, TS: now.Add(-2 * time.Hour), PID: 7, Path: "/a"})
	st.PutEvent(event.Event{Kind: event.KindFileOpen, TS: now.Add(-5 * time.Minute), PID: 7, Path: "/b"})
	st.PutEvent(event.Event{Kind: event.KindFileOpen, TS: now.Add(-1 * time.Hour), PID: 9, Path: "/c"})

	got := st.LastEventTimes([]int32{7, 9, 42})
	ts7, err := time.Parse(time.RFC3339Nano, got[7])
	if err != nil || time.Since(ts7) > 10*time.Minute {
		t.Fatalf("pid 7 last event should be the newest insert, got %q", got[7])
	}
	if got[9] == "" {
		t.Fatal("pid 9 missing")
	}
	if _, ok := got[42]; ok {
		t.Fatal("pid without events must be absent, not empty-string")
	}
	if len(st.LastEventTimes(nil)) != 0 {
		t.Fatal("empty pid list must return empty map")
	}
}

func TestGuardPathAllows(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), filepath.Join(dir, "e.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.PutGuardPathAllow(GuardPathAllow{Agent: "claude", RuleID: "ssh-keys", Path: "/Users/x/.ssh/config"})
	if !s.GuardPathAllowed("claude", "ssh-keys", "/Users/x/.ssh/config") {
		t.Fatal("exact path must be allowed")
	}
	// Descendants inherit: an allow on a path covers everything under it…
	if !s.GuardPathAllowed("claude", "ssh-keys", "/Users/x/.ssh/config/main.conf") {
		t.Fatal("descendant of an allowed path must be allowed")
	}
	// …but path-adjacent siblings are NOT descendants ("config.d" shares a
	// prefix with "config" without being under it) — the allow is exactly as
	// wide as the operator chose.
	if s.GuardPathAllowed("claude", "ssh-keys", "/Users/x/.ssh/config.d/host.conf") {
		t.Fatal("prefix-colliding sibling (config.d vs config) must NOT be allowed")
	}
	// Siblings don't: the allow is exactly as wide as the operator chose.
	if s.GuardPathAllowed("claude", "ssh-keys", "/Users/x/.ssh/id_ed25519") {
		t.Fatal("sibling path must NOT be allowed")
	}
	// Other agents/rules are unaffected.
	if s.GuardPathAllowed("cursor", "ssh-keys", "/Users/x/.ssh/config") ||
		s.GuardPathAllowed("claude", "env-files", "/Users/x/.ssh/config") {
		t.Fatal("allow must be scoped to the agent+rule pair")
	}
	// Idempotent upsert, list, revoke.
	s.PutGuardPathAllow(GuardPathAllow{Agent: "claude", RuleID: "ssh-keys", Path: "/Users/x/.ssh/config"})
	if got := s.ListGuardPathAllows(100); len(got) != 1 {
		t.Fatalf("upsert must not duplicate, got %d rows", len(got))
	}
	if !s.DeleteGuardPathAllow("claude", "ssh-keys", "/Users/x/.ssh/config") {
		t.Fatal("delete of an existing allow must report removed")
	}
	if s.GuardPathAllowed("claude", "ssh-keys", "/Users/x/.ssh/config") {
		t.Fatal("revoked path must not be allowed")
	}
	// Read failure fails closed, never open.
	if s.GuardPathAllowed("claude", "ssh-keys", "") {
		t.Fatal("empty path must never be allowed")
	}
}

func TestAcknowledgeRuleHost(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), filepath.Join(dir, "e.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Two flags of the same rule, different hosts; one acknowledged already.
	s.PutFlag(model.Flag{ID: "f1", Rule: "sensitive-read-then-connect", Severity: 3, PID: 7, Agent: "cursor",
		Evidence: model.EvidenceFromStrings("cursor (pid 7) read /a at 2026-09-11T12:00:00Z", "then connected to localhost:62381 at 2026-09-11T12:00:01Z")})
	s.PutFlag(model.Flag{ID: "f2", Rule: "sensitive-read-then-connect", Severity: 3, PID: 7, Agent: "cursor",
		Evidence: model.EvidenceFromStrings("then connected to api.example.com:443 at 2026-09-11T12:00:02Z")})
	s.PutFlag(model.Flag{ID: "f3", Rule: "sensitive-read-then-connect", Severity: 3, PID: 7, Agent: "cursor",
		Evidence: model.EvidenceFromStrings("then connected to 127.0.0.1:9999 at 2026-09-11T12:00:03Z")})
	s.PutFlag(model.Flag{ID: "f4", Rule: "proxy-secret-leak", Severity: 3, PID: 7, Agent: "cursor",
		Evidence: model.EvidenceFromStrings("then connected to localhost:1234 at 2026-09-11T12:00:04Z")})

	n := s.AcknowledgeRuleHost("sensitive-read-then-connect", "localhost", "")
	// f1 (localhost) + f3 (127.0.0.1 — localhost alias) ack'd; f2 (other host) + f4 (other rule) untouched.
	if n != 2 {
		t.Fatalf("acknowledged %d flags; want 2", n)
	}
	got, _ := s.GetFlag("f1")
	if !got.Acknowledged {
		t.Fatal("f1 must be acknowledged")
	}
	got2, _ := s.GetFlag("f2")
	if got2.Acknowledged {
		t.Fatal("f2 (different host) must NOT be acknowledged")
	}
	got3, _ := s.GetFlag("f3")
	if !got3.Acknowledged {
		t.Fatal("f3 (127.0.0.1 alias of localhost) must be acknowledged")
	}
	// Idempotent: second run acknowledges nothing new.
	if n2 := s.AcknowledgeRuleHost("sensitive-read-then-connect", "localhost", ""); n2 != 0 {
		t.Fatalf("second pass acknowledged %d; want 0", n2)
	}
}

// The rule-level disposition (host "*") sweeps EVERY open flag of the rule,
// regardless of cited host — the keychain-noise escape hatch.
func TestAcknowledgeRuleHostWildcard(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "w.db"), filepath.Join(dir, "w.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.PutFlag(model.Flag{ID: "k1", Rule: "keychain-access", Severity: 1, PID: 7, Agent: "codex",
		Evidence: model.EvidenceFromStrings("codex (pid 7) accessed keychain file /Users/x/Library/Keychains/login.keychain-db at 2026-09-15T10:00:00Z")})
	s.PutFlag(model.Flag{ID: "k2", Rule: "keychain-access", Severity: 1, PID: 9, Agent: "cursor",
		Evidence: model.EvidenceFromStrings("cursor (pid 9) accessed keychain file /Users/x/Library/Keychains/login.keychain-db at 2026-09-15T10:01:00Z")})
	s.PutFlag(model.Flag{ID: "o1", Rule: "proxy-secret-leak", Severity: 3, PID: 7, Agent: "codex",
		Evidence: model.EvidenceFromStrings("anthropic-key in request body to api.example.com")})

	if n := s.AcknowledgeRuleHost("keychain-access", "*", ""); n != 2 {
		t.Fatalf("wildcard ack = %d, want 2", n)
	}
	if f, _ := s.GetFlag("k1"); !f.Acknowledged {
		t.Fatal("k1 must be acknowledged")
	}
	if f, _ := s.GetFlag("k2"); !f.Acknowledged {
		t.Fatal("k2 must be acknowledged")
	}
	if f, _ := s.GetFlag("o1"); f.Acknowledged {
		t.Fatal("other rules must be untouched by the wildcard")
	}
}

// The dashboard's Acknowledge/Resolve buttons write workflow columns on
// incidents. Regression: those columns were missing from the incidents
// schema entirely ("no such column: status") — every dismiss was dead.
func TestIncidentStatusWorkflow(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), filepath.Join(dir, "e.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	report := model.IncidentReport{ID: "inc-1", FlagID: "f1", PID: 7, Risk: "HIGH",
		Summary: "test", RotateList: nil, TouchedFiles: nil, Connections: nil}
	s.PutIncident(report)

	// Acknowledge.
	ok, err := s.SetIncidentStatus("inc-1", "acknowledged", "")
	if err != nil || !ok {
		t.Fatalf("acknowledge failed: %v ok=%v", err, ok)
	}
	wf, found := s.IncidentStatus("inc-1")
	if !found || wf.Status != "acknowledged" {
		t.Fatalf("status = %+v found=%v", wf, found)
	}

	// Resolve with note.
	ok, err = s.SetIncidentStatus("inc-1", "resolved", "verified benign")
	if err != nil || !ok {
		t.Fatalf("resolve failed: %v ok=%v", err, ok)
	}
	wf, _ = s.IncidentStatus("inc-1")
	if wf.Status != "resolved" {
		t.Fatalf("status after resolve = %q", wf.Status)
	}
	if wf.ResolutionNote != "verified benign" {
		t.Fatalf("resolution note = %q", wf.ResolutionNote)
	}
}

// Trace kinds are exempt from the global row cap: socket churn at 73% of
// rows evicted a 7-day trace window down to 15 hours (the audit). The cap
// now counts OS-event kinds only; trace kinds have their own budgets.
func TestPruneExemptsTraceKindsFromCountCap(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now()
	// 60 OS events (conn churn) vs 20 trace rows: a cap of 50 must evict OS
	// rows but leave every trace row.
	for i := 0; i < 60; i++ {
		s.PutEvent(event.Event{Kind: event.KindConnOpen, PID: 1, TS: now})
	}
	for i := 0; i < 20; i++ {
		s.PutEvent(event.Event{Kind: event.KindToolCall, TS: now, SessionID: "s", CallID: fmt.Sprintf("c%d", i), ToolName: "Bash", ToolStatus: "ok"})
	}
	setKindBudget(t, int(event.KindConnOpen), 50)
	s.PruneEvents()

	kind := int(event.KindToolCall)
	if n := len(s.QueryEvents(EventFilter{Kind: &kind})); n != 20 {
		t.Fatalf("trace rows after prune = %d, want 20 (cap must not evict trace)", n)
	}
	conn := int(event.KindConnOpen)
	if n := len(s.QueryEvents(EventFilter{Kind: &conn})); n >= 60 {
		t.Fatalf("OS rows after prune = %d, want evicted down to the cap", n)
	}
}

func setKindBudget(t *testing.T, kind, budget int) {
	t.Helper()
	prev, had := kindBudgets[kind]
	kindBudgets[kind] = budget
	t.Cleanup(func() {
		if had {
			kindBudgets[kind] = prev
		} else {
			delete(kindBudgets, kind)
		}
	})
}

func countKind(t *testing.T, s *Store, kind int) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE kind = ?`, kind).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A burst in one kind must not evict another kind's rows: the file-open
// burst is trimmed to its own budget and every other kind survives intact.
func TestPrunePerKindBudgetsIsolateBursts(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	setKindBudget(t, int(event.KindFileOpen), 50)

	now := time.Now()
	put := func(kind event.Kind, n int) {
		for i := 0; i < n; i++ {
			s.PutEvent(event.Event{Kind: kind, PID: 1, TS: now})
		}
	}
	put(event.KindPluginAction, 100)
	put(event.KindConnOpen, 100)
	put(event.KindTranscriptHit, 100)
	put(event.KindFileOpen, 100)

	s.PruneEvents()

	for _, c := range []struct {
		kind event.Kind
		want int
	}{
		{event.KindPluginAction, 100},
		{event.KindConnOpen, 100},
		{event.KindTranscriptHit, 100},
		{event.KindFileOpen, 50},
	} {
		if got := countKind(t, s, int(c.kind)); got != c.want {
			t.Errorf("kind %s: kept %d, want %d", c.kind, got, c.want)
		}
	}
}

// A build's file flood trims the kind to its budget, but the record rows it
// would have pushed out stay.
func TestPruneKeepsRecordRowsPastTheBudget(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	setKindBudget(t, int(event.KindFileOpen), 50)

	now := time.Now()
	for i := 0; i < 5; i++ {
		s.PutEvent(event.Event{Kind: event.KindFileOpen, PID: 1, TS: now, Path: "/Users/x/.ssh/id_rsa", Record: true})
	}
	for i := 0; i < 100; i++ {
		s.PutEvent(event.Event{Kind: event.KindFileOpen, PID: 1, TS: now, Path: "/Users/x/p/node_modules/a.js"})
	}
	s.PruneEvents()

	if got := countKind(t, s, int(event.KindFileOpen)); got != 55 {
		t.Fatalf("file-open rows = %d, want the newest 50 plus 5 record rows", got)
	}
	if got := countRecord(t, s, int(event.KindFileOpen)); got != 5 {
		t.Fatalf("record rows = %d, want all 5", got)
	}
}

// Record rows keep their own newest recordBudget.
func TestPruneCapsRecordRows(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	prev := recordBudget
	recordBudget = 3
	t.Cleanup(func() { recordBudget = prev })

	now := time.Now()
	for i := 0; i < 10; i++ {
		s.PutEvent(event.Event{Kind: event.KindFileOpen, PID: int32(i), TS: now, Path: "/Users/x/.aws/credentials", Record: true})
	}
	s.PruneEvents()

	var pids []int
	rows, err := s.db.Query(`SELECT pid FROM events WHERE kind = ? AND record = 1 ORDER BY id`, int(event.KindFileOpen))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var p int
		if err := rows.Scan(&p); err != nil {
			t.Fatal(err)
		}
		pids = append(pids, p)
	}
	if !slices.Equal(pids, []int{7, 8, 9}) {
		t.Fatalf("record rows kept = %v, want the newest three [7 8 9]", pids)
	}
}

func countRecord(t *testing.T, s *Store, kind int) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE kind = ? AND record = 1`, kind).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Pruning walks the kinds present in the table, so a kind outside the
// event enum is still bounded.
func TestPruneBudgetsApplyToUnlistedKinds(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	setKindBudget(t, 99, 3)

	for i := 0; i < 10; i++ {
		s.PutEvent(event.Event{Kind: event.Kind(99), PID: 1, TS: time.Now()})
	}
	s.PruneEvents()

	if got := countKind(t, s, 99); got != 3 {
		t.Fatalf("kind 99 rows after prune = %d, want 3", got)
	}
}

// The insert-driven prune runs at most once per pruneMinInterval: a
// high-rate producer crosses the 1000-insert mark every second, and each
// prune scans the table.
func TestInsertDrivenPruneGatedByMinInterval(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	setKindBudget(t, int(event.KindExec), 100)
	put := func(n int) {
		for i := 0; i < n; i++ {
			s.PutEvent(event.Event{Kind: event.KindExec, PID: 1, TS: time.Now()})
		}
	}

	put(1000)
	if got := countKind(t, s, int(event.KindExec)); got != 100 {
		t.Fatalf("after first 1000 inserts: %d rows, want 100 (first prune runs)", got)
	}
	put(1000)
	if got := countKind(t, s, int(event.KindExec)); got != 1100 {
		t.Fatalf("second 1000 inserts inside the interval: %d rows, want 1100 (prune gated)", got)
	}

	prev := pruneMinInterval
	pruneMinInterval = 0
	t.Cleanup(func() { pruneMinInterval = prev })
	put(1000)
	if got := countKind(t, s, int(event.KindExec)); got != 100 {
		t.Fatalf("after the interval: %d rows, want 100", got)
	}
}

// Budget pruning and the kind walk seek the (kind, id) index instead of
// scanning the table.
func TestPruneBudgetQueryUsesKindIndex(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	joined := queryPlan(t, s, `DELETE FROM events WHERE kind = ? AND record = 0 AND id <
		(SELECT id FROM events WHERE kind = ? ORDER BY id DESC LIMIT 1 OFFSET ?)`, 0, 0, 9)
	if strings.Contains(joined, "SCAN events") || !strings.Contains(joined, "idx_events_kind_id") {
		t.Fatalf("budget delete plan = %q, want index seeks on idx_events_kind_id", joined)
	}
	joined = queryPlan(t, s, `DELETE FROM events WHERE kind = ? AND record = 1 AND id <
		(SELECT id FROM events WHERE kind = ? AND record = 1 ORDER BY id DESC LIMIT 1 OFFSET ?)`, 0, 0, 9)
	if strings.Contains(joined, "SCAN events") || !strings.Contains(joined, "idx_events_record") {
		t.Fatalf("record delete plan = %q, want index seeks on idx_events_record", joined)
	}
}

func queryPlan(t *testing.T, s *Store, q string, args ...any) string {
	t.Helper()
	rows, err := s.db.Query(`EXPLAIN QUERY PLAN `+q, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return strings.Join(plan, " | ")
}

// The flag-explain lookup (one kind in one session around an anchor) seeks
// (session_id, kind) instead of walking every row of the kind.
func TestSessionKindLookupUsesSessionKindIndex(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	plan := queryPlan(t, s, `SELECT kind FROM events WHERE 1=1 AND kind = ? AND session_id = ?
		AND datetime(ts) >= datetime(?) AND datetime(ts) <= datetime(?) ORDER BY id DESC LIMIT ?`,
		12, "sess", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", 200)
	if !strings.Contains(plan, "idx_events_session_kind_id") {
		t.Fatalf("session+kind lookup plan = %q, want idx_events_session_kind_id", plan)
	}
}

// Planner statistics are written at open and after a gated prune, so a
// kind+pid lookup takes the pid index instead of walking the kind.
func TestPlannerStatsRouteKindPidLookupToPidIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.db")
	s, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i := 0; i < 3000; i++ {
		s.PutEvent(event.Event{Kind: event.Kind(i % 4), PID: int32(i + 1), TS: now})
	}
	s.Close()

	s, err = Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var statRows int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_stat1 WHERE tbl = 'events'`).Scan(&statRows); err != nil {
		t.Fatalf("sqlite_stat1: %v (planner stats never written)", err)
	}
	if statRows == 0 {
		t.Fatal("no planner stats for events")
	}
	plan := queryPlan(t, s, `SELECT kind FROM events WHERE 1=1 AND kind = ? AND pid = ? ORDER BY id DESC LIMIT ?`, 0, 42, 50)
	if !strings.Contains(plan, "idx_events_pid_ts") {
		t.Fatalf("kind+pid lookup plan = %q, want idx_events_pid_ts", plan)
	}
}

// WAL with synchronous=NORMAL: commits skip the per-transaction fsync.
func TestOpenUsesWALSynchronousNormal(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var mode string
	if err := s.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	var sync int
	if err := s.db.QueryRow(`PRAGMA synchronous`).Scan(&sync); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" || sync != 1 {
		t.Fatalf("journal_mode=%q synchronous=%d, want wal and 1 (NORMAL)", mode, sync)
	}
}

// A transcript re-read replays the same turn/model-call record with the same
// timestamp; the second insert must be ignored, not double-counted.
func TestTurnAndModelCallDedupeOnSessionTS(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ts := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	turn := event.Event{Kind: event.KindTurn, TS: ts, SessionID: "s1"}
	s.PutEvent(turn)
	s.PutEvent(turn)
	mc := event.Event{Kind: event.KindModelCall, TS: ts, SessionID: "s1", Model: "claude-x"}
	s.PutEvent(mc)
	s.PutEvent(mc)

	turns := 0
	s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE kind = 13 AND session_id = 's1'`).Scan(&turns)
	if turns != 1 {
		t.Fatalf("turns = %d, want 1 (replay ignored)", turns)
	}
	calls := 0
	s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE kind = 14 AND session_id = 's1'`).Scan(&calls)
	if calls != 1 {
		t.Fatalf("model calls = %d, want 1 (replay ignored)", calls)
	}
	// Other kinds still insert duplicates (no dedupe).
	s.PutEvent(event.Event{Kind: event.KindFileOpen, TS: ts, PID: 1})
	s.PutEvent(event.Event{Kind: event.KindFileOpen, TS: ts, PID: 1})
	opens := 0
	s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE kind = 0`).Scan(&opens)
	if opens != 2 {
		t.Fatalf("file opens = %d, want 2 (no dedupe for other kinds)", opens)
	}
}

// EventFilter.Until bounds the window from above, so a nearest-event lookup
// is not starved by a long session's newer rows.
func TestQueryEventsUntil(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	for i := 0; i < 5; i++ {
		s.PutEvent(event.Event{Kind: event.KindToolCall, TS: base.Add(time.Duration(i) * time.Minute), SessionID: "s", ToolName: fmt.Sprint(i), CallID: fmt.Sprint("c", i)})
	}
	got := s.QueryEvents(EventFilter{SessionID: "s", Since: base.Add(time.Minute).Format(time.RFC3339), Until: base.Add(3 * time.Minute).Format(time.RFC3339)})
	if len(got) != 3 || got[0].ToolName != "3" || got[2].ToolName != "1" {
		t.Fatalf("window = %+v, want tools 3,2,1", got)
	}
}

// IncidentIDForFlag finds the incident a flag opened or was aggregated into.
func TestIncidentIDForFlag(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.PutIncident(model.IncidentReport{ID: "inc-1", FlagID: "f1", Rule: "r", Timestamp: time.Now()})
	s.AggregateIntoIncident("inc-1", "f2", time.Now())
	for flagID, want := range map[string]string{"f1": "inc-1", "f2": "inc-1", "f3": ""} {
		got, ok := s.IncidentIDForFlag(flagID)
		if got != want || ok != (want != "") {
			t.Errorf("IncidentIDForFlag(%s) = %q,%v, want %q", flagID, got, ok, want)
		}
	}
}

func TestReattributeFlagsRelabelsUntaggedRowsForPIDInWindow(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	since := now.Add(-time.Hour)
	put := func(id string, pid int32, agent string, ts time.Time) {
		s.PutFlag(model.Flag{ID: id, Rule: "keychain-access", Severity: 3, TS: ts, PID: pid, Agent: agent})
	}
	put("in-1", 42, "untagged:node", now.Add(-5*time.Minute))
	put("in-2", 42, "untagged:claude 2.1.280", now.Add(-30*time.Minute))
	put("old", 42, "untagged:node", now.Add(-2*time.Hour))
	put("other-pid", 43, "untagged:node", now.Add(-5*time.Minute))
	put("tagged", 42, "codex", now.Add(-5*time.Minute))

	if n := s.ReattributeFlags(42, "claude", since); n != 2 {
		t.Fatalf("ReattributeFlags = %d, want 2", n)
	}
	want := map[string]string{
		"in-1": "claude", "in-2": "claude",
		"old": "untagged:node", "other-pid": "untagged:node", "tagged": "codex",
	}
	for id, agent := range want {
		fl, ok := s.GetFlag(id)
		if !ok || fl.Agent != agent {
			t.Errorf("flag %s agent = %q (found %v), want %q", id, fl.Agent, ok, agent)
		}
	}
	if n := s.ReattributeFlags(42, "claude", since); n != 0 {
		t.Fatalf("second ReattributeFlags = %d, want 0", n)
	}
}

// An agent-scoped mute acknowledges only that agent's open flags of the rule.
func TestAcknowledgeRuleHostScopedToAgent(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "a.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.PutFlag(model.Flag{ID: "k1", Rule: "keychain-access", Severity: 1, PID: 7, Agent: "codex"})
	s.PutFlag(model.Flag{ID: "k2", Rule: "keychain-access", Severity: 1, PID: 9, Agent: "cursor"})
	if n := s.AcknowledgeRuleHost("keychain-access", "*", "codex"); n != 1 {
		t.Fatalf("agent-scoped ack = %d, want 1", n)
	}
	if f, _ := s.GetFlag("k1"); !f.Acknowledged {
		t.Fatal("codex flag must be acknowledged")
	}
	if f, _ := s.GetFlag("k2"); f.Acknowledged {
		t.Fatal("cursor flag must stay open")
	}
}

func TestFlagProcessAndAckReasonRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	proc := &model.FlagProcess{Exe: "/bin/zsh", Name: "zsh", Args0: "-zsh", PPID: 200, Launcher: "Claude.app › claude-code 2.1.281"}
	s.PutFlag(model.Flag{ID: "f1", Rule: "r", Severity: 3, TS: time.Now(), PID: 7, Agent: "claude", Process: proc})
	s.PutFlag(model.Flag{ID: "f2", Rule: "r", Severity: 3, TS: time.Now(), PID: 8, Agent: "claude"})
	if got, _ := s.GetFlag("f1"); got.Process == nil || *got.Process != *proc {
		t.Fatalf("GetFlag process = %+v, want %+v", got.Process, proc)
	}
	if got, _ := s.GetFlag("f2"); got.Process != nil {
		t.Fatalf("flag without a snapshot served process %+v", got.Process)
	}
	if n := s.AcknowledgeFlagsReason([]string{"f1"}, "why"); n != 1 {
		t.Fatalf("acknowledged = %d", n)
	}
	for _, f := range s.QueryFlags(FlagFilter{Limit: 10}) {
		switch f.ID {
		case "f1":
			if !f.Acknowledged || f.AckReason != "why" || f.Process == nil || f.Process.Launcher != proc.Launcher {
				t.Fatalf("f1 = %+v", f)
			}
		case "f2":
			if f.Acknowledged || f.AckReason != "" {
				t.Fatalf("f2 = %+v", f)
			}
		}
	}
}
