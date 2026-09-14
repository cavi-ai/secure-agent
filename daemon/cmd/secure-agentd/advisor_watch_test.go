package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// The hot-reload loop swaps the advisor stack when config.yaml changes, and
// keeps the CURRENT stack when the config is unreadable (a half-written file
// must never disable a working advisor).
func TestWatchAdvisorConfigHotSwaps(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	store, err := store.Open(filepath.Join(dir, "e.db"), filepath.Join(dir, "e.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	write := func(enabled bool) {
		src := "advisor:\n  enabled: " + boolYAML(enabled) +
			"\n  managed: false\n  endpoint: \"http://127.0.0.1:11434\"\n  model: \"m\"\n  timeout_ms: 5000\n"
		if err := os.WriteFile(cfgPath, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write(true)
	stk := &advisorStackHolder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchAdvisorConfig(ctx, cfgPath, store, stk)

	// Initial state: enabled.
	waitFor(t, 5*time.Second, func() bool { return stk.Load().Sub != nil })

	// Flip to disabled: the swap must drop the subscriber.
	write(false)
	waitFor(t, 5*time.Second, func() bool { return stk.Load().Sub == nil })

	// Flip back on: it returns.
	write(true)
	waitFor(t, 5*time.Second, func() bool { return stk.Load().Sub != nil })
}

// A corrupt config mid-write must NOT disturb the live stack.
func TestWatchAdvisorConfigSurvivesCorruptConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	store, err := store.Open(filepath.Join(dir, "e.db"), filepath.Join(dir, "e.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	os.WriteFile(cfgPath, []byte("advisor:\n  enabled: true\n  managed: false\n  endpoint: \"http://127.0.0.1:9999\"\n  model: \"m\"\n"), 0o600)
	stk := &advisorStackHolder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchAdvisorConfig(ctx, cfgPath, store, stk)
	waitFor(t, 5*time.Second, func() bool { return stk.Load().Sub != nil })

	// Corrupt write (truncated mid-key).
	os.WriteFile(cfgPath, []byte("advisor:\n  enabled: [broken\n  man"), 0o600)
	time.Sleep(2500 * time.Millisecond)
	if stk.Load().Sub == nil {
		t.Fatal("corrupt config must keep the current advisor stack")
	}

	// Recovery: a valid config resumes swaps.
	os.WriteFile(cfgPath, []byte("advisor:\n  enabled: false\n"), 0o600)
	waitFor(t, 5*time.Second, func() bool { return stk.Load().Sub == nil })
}

// The fingerprint key must distinguish all advisor-relevant fields — a key
// collision would silently skip a real change (e.g. model swap).
func TestAdvisorConfigKeyDistinguishesFields(t *testing.T) {
	a := config.AdvisorConfig{Endpoint: "http://a", Model: "m1", ManagedModel: "mm", Enabled: true}
	b := a
	b.Model = "other"
	if advisorConfigKey(a) == advisorConfigKey(b) {
		t.Fatal("key must differ when the model changes")
	}
	c := a
	c.Enabled = false
	if advisorConfigKey(a) == advisorConfigKey(c) {
		t.Fatal("key must differ when enabled changes")
	}
}

func boolYAML(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}
