package correlate

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestMuteSuppressesFlagAndCounts(t *testing.T) {
	c := newTestCorrelator(t)
	c.SetMuteChecker(func(rule, host string) bool {
		return rule == "sensitive-read-then-connect" && host == "evil.example.com"
	})

	base := time.Unix(1_700_000_000, 0)
	c.Observe(event.Event{Kind: event.KindFileOpen, PID: 200, TS: base, Path: "/Users/x/proj/.env"})
	c.Observe(event.Event{Kind: event.KindConnOpen, PID: 200, TS: base.Add(3 * time.Second), RemoteHost: "evil.example.com", RemotePort: 443})

	if got := c.MutedCount(); got != 1 {
		t.Fatalf("muted pair must be counted, got %d", got)
	}
	// Unmuted host still flags.
	c.Observe(event.Event{Kind: event.KindFileOpen, PID: 200, TS: base.Add(10 * time.Second), Path: "/Users/x/proj/.env"})
	f := c.Observe(event.Event{Kind: event.KindConnOpen, PID: 200, TS: base.Add(13 * time.Second), RemoteHost: "other.example.com", RemotePort: 443})
	if len(f) != 1 {
		t.Fatalf("unmuted host must still flag, got %d flags", len(f))
	}
}

func TestMuteStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "muted.json")
	s := NewMuteStore(path)
	if err := s.Add("proxy-prompt-injection", "blog.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.Add("proxy-prompt-injection", "blog.example.com"); err != nil { // idempotent
		t.Fatal(err)
	}
	m := NewMuteStore(path).Load()
	if len(m["proxy-prompt-injection"]) != 1 {
		t.Fatalf("expected 1 entry: %v", m)
	}
	if err := s.Remove("proxy-prompt-injection", "blog.example.com"); err != nil {
		t.Fatal(err)
	}
	if len(NewMuteStore(path).Load()) != 0 {
		t.Fatal("remove must empty the store")
	}
	// Removing an absent pair is a no-op, not an error.
	if err := s.Remove("nope", "nope.example.com"); err != nil {
		t.Fatal(err)
	}
}
