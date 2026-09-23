package correlate

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestUninspectedSummaryCounts(t *testing.T) {
	c := newTestCorrelator(t)
	// Recent base: the summary prunes entries silent past the retention, so a
	// fixed 2023 timestamp would be swept before the assertion.
	base := time.Now().Add(-time.Hour)
	for i := 0; i < 5; i++ {
		c.Observe(event.Event{Kind: event.KindConnOpen, PID: 200, TS: base.Add(time.Duration(i) * time.Second), RemoteHost: "logs.example.com", RemotePort: 443})
	}
	c.Observe(event.Event{Kind: event.KindConnOpen, PID: 200, TS: base, RemoteHost: "once.example.com", RemotePort: 443})

	sum := c.UninspectedEgressSummary()
	if len(sum) != 2 {
		t.Fatalf("expected 2 endpoints, got %v", sum)
	}
	if sum[0].Host != "logs.example.com" || sum[0].Count != 5 {
		t.Fatalf("most frequent first with count: %+v", sum[0])
	}
	if sum[0].Agent != "cursor" {
		t.Fatalf("agent should be resolved through the tagger, got %q", sum[0].Agent)
	}
}

func TestAllowlistOverrideMakesHostVendor(t *testing.T) {
	c := newTestCorrelator(t)
	c.Observe(event.Event{Kind: event.KindConnOpen, PID: 200, TS: time.Now(), RemoteHost: "api.github.com", RemotePort: 443})
	if n := c.UninspectedEgressCount(); n != 1 {
		t.Fatalf("pre-approval: expected 1 uninspected, got %d", n)
	}

	c.SetAllowlistOverrides(func(agent string) []string {
		if agent == "cursor" {
			return []string{"api.github.com"}
		}
		return nil
	})
	c.NoteAllowlistAdded("cursor", "api.github.com")

	if n := c.UninspectedEgressCount(); n != 0 {
		t.Fatalf("approval must purge the blind-spot entry, got %d", n)
	}
	// New connections to the approved host no longer count as uninspected.
	c.Observe(event.Event{Kind: event.KindConnOpen, PID: 200, TS: time.Now(), RemoteHost: "api.github.com", RemotePort: 443})
	if n := c.UninspectedEgressCount(); n != 0 {
		t.Fatalf("approved host must read as vendor traffic, got %d uninspected", n)
	}
	// Subdomain of an approved host also counts (same rule as config allowlists).
	if !c.isVendorHost("cursor", "uploads.api.github.com") {
		t.Fatal("subdomain of an approved host must match")
	}
	// But a lookalike domain must not.
	if c.isVendorHost("cursor", "api.github.com.evil.xyz") {
		t.Fatal("suffix-spoofing domain must NOT match the override")
	}
}

func TestAllowlistStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist-overrides.json")
	s := NewAllowlistStore(path)
	if err := s.Add("cursor", "api.github.com"); err != nil {
		t.Fatal(err)
	}
	// Idempotent re-add.
	if err := s.Add("cursor", "api.github.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.Add("claude", "registry.npmjs.org"); err != nil {
		t.Fatal(err)
	}
	fresh := NewAllowlistStore(path).Load()
	if len(fresh["cursor"]) != 1 || fresh["cursor"][0] != "api.github.com" {
		t.Fatalf("cursor overrides wrong: %v", fresh)
	}
	if len(fresh["claude"]) != 1 {
		t.Fatalf("claude overrides wrong: %v", fresh)
	}
	// Permissions: 0600 — the file encodes policy.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("file missing after write: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("allowlist overrides must be 0600, got %o", info.Mode().Perm())
	}
}

// Allows applies the correlator's vendor-host match rule: exact host or a
// dot-boundary suffix, case-insensitive, per agent.
func TestAllowlistStoreAllows(t *testing.T) {
	s := NewAllowlistStore(filepath.Join(t.TempDir(), "allow.json"))
	if s.Allows("claude", "api.example.com") {
		t.Fatal("empty store allows nothing")
	}
	if err := s.Add("claude", "Example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.Add("claude", "2606:4700:20::681a:4a4"); err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]bool{
		"example.com":            true,
		"API.example.com":        true,
		"badexample.com":         false,
		"example.com.evil.net":   false,
		"2606:4700:20::681a:4a4": true,
	} {
		if got := s.Allows("claude", host); got != want {
			t.Errorf("Allows(claude, %s) = %v, want %v", host, got, want)
		}
	}
	if s.Allows("codex", "example.com") {
		t.Error("approvals are per agent")
	}
}
