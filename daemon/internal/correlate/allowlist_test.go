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
	base := time.Unix(1_700_000_000, 0)
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
