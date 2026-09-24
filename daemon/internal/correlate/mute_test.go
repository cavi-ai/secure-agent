package correlate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestMuteSuppressesFlagAndCounts(t *testing.T) {
	c := newTestCorrelator(t)
	c.SetMuteChecker(func(rule, host, agent string) bool {
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
	if err := s.Add("proxy-prompt-injection", "blog.example.com", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Add("proxy-prompt-injection", "blog.example.com", ""); err != nil { // idempotent
		t.Fatal(err)
	}
	m := NewMuteStore(path).Load()
	if len(m["proxy-prompt-injection"]) != 1 {
		t.Fatalf("expected 1 entry: %v", m)
	}
	if err := s.Remove("proxy-prompt-injection", "blog.example.com", ""); err != nil {
		t.Fatal(err)
	}
	if len(NewMuteStore(path).Load()) != 0 {
		t.Fatal("remove must empty the store")
	}
	// Removing an absent pair is a no-op, not an error.
	if err := s.Remove("nope", "nope.example.com", ""); err != nil {
		t.Fatal(err)
	}
}

func TestMuteStoreAgentScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "muted.json")
	// A file written before per-agent mutes: bare host strings.
	if err := os.WriteFile(path, []byte(`{"proxy-prompt-injection":["blog.example.com"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewMuteStore(path)
	if !s.Muted("proxy-prompt-injection", "blog.example.com", "codex") || !s.Muted("proxy-prompt-injection", "blog.example.com", "claude") {
		t.Fatal("a mute without agent must match every agent")
	}
	if err := s.Add("keychain-access", "*", "codex"); err != nil {
		t.Fatal(err)
	}
	if err := s.Add("keychain-access", "*", "codex"); err != nil { // idempotent
		t.Fatal(err)
	}
	if !s.Muted("keychain-access", "*", "codex") {
		t.Fatal("agent mute must match its agent")
	}
	if s.Muted("keychain-access", "*", "claude") {
		t.Fatal("agent mute must not match another agent")
	}
	m := NewMuteStore(path).Load()
	if got := m["keychain-access"]; len(got) != 1 || got[0] != (Mute{Host: "*", Agent: "codex"}) {
		t.Fatalf("keychain-access entries = %+v", got)
	}
	if got := m["proxy-prompt-injection"]; len(got) != 1 || got[0] != (Mute{Host: "blog.example.com"}) {
		t.Fatalf("legacy entry = %+v", got)
	}
	// An every-agent mute stays a bare string on disk.
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"blog.example.com"`) || strings.Contains(string(data), `"host": "blog.example.com"`) {
		t.Fatalf("every-agent mute must stay a bare host string: %s", data)
	}
	// Removing the agent mute leaves an every-agent mute of the same pair alone.
	if err := s.Add("keychain-access", "*", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("keychain-access", "*", "codex"); err != nil {
		t.Fatal(err)
	}
	if got := s.Load()["keychain-access"]; len(got) != 1 || got[0] != (Mute{Host: "*"}) {
		t.Fatalf("after removing the codex mute: %+v", got)
	}
}

// A keychain-class mute for one agent counts that agent's access and still
// flags another agent's.
func TestKeychainMuteForOneAgentStillFlagsAnother(t *testing.T) {
	c := newTestCorrelator(t) // pid 200 = cursor
	store := NewMuteStore(filepath.Join(t.TempDir(), "muted.json"))
	if err := store.Add("keychain-access", "*", "cursor"); err != nil {
		t.Fatal(err)
	}
	c.SetMuteChecker(store.Muted)
	base := time.Now()
	const kc = "/Users/x/Library/Keychains/login.keychain-db"

	if f := c.Observe(event.Event{Kind: event.KindFileOpen, PID: 200, TS: base, Path: kc}); len(f) != 0 {
		t.Fatalf("cursor's keychain access is muted, got %+v", f)
	}
	if got := c.MutedCount(); got != 1 {
		t.Fatalf("muted count = %d, want 1", got)
	}
	f := c.Observe(event.Event{Kind: event.KindFileOpen, PID: 999, TS: base, Path: kc, ExePath: "/Users/x/.local/bin/codex"})
	if len(f) != 1 || f[0].Rule != "keychain-access" || f[0].Agent != "codex" {
		t.Fatalf("codex keychain access must still flag, got %+v", f)
	}
}
