package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/fleet"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
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
	go watchConfig(ctx, cfgPath, configWatchDeps{st: store, stk: stk, pub: fleet.NewPublisher(), fleetCfg: &fleetConfigHolder{}})

	// Initial state: enabled.
	waitFor(t, 5*time.Second, func() bool { return stk.Load().Sub != nil })

	// Flip to disabled: the swap must drop the subscriber.
	write(false)
	waitFor(t, 5*time.Second, func() bool { return stk.Load().Sub == nil })

	// Flip back on: it returns.
	write(true)
	waitFor(t, 5*time.Second, func() bool { return stk.Load().Sub != nil })
}

func TestWatchConfigKeepsAlreadyAppliedStartupState(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	st, err := store.Open(filepath.Join(dir, "e.db"), filepath.Join(dir, "e.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := os.WriteFile(cfgPath, []byte("advisor:\n  enabled: true\n  managed: false\n  endpoint: \"http://127.0.0.1:11434\"\n  model: \"startup\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadStrict(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	initial := setupAdvisor(cfg, st)
	stk := &advisorStackHolder{}
	stk.Store(initial)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchConfig(ctx, cfgPath, configWatchDeps{
		st: st, stk: stk, pub: fleet.NewPublisher(), fleetCfg: &fleetConfigHolder{}, initialConfig: &cfg,
	})

	time.Sleep(300 * time.Millisecond)
	if stk.Load().Sub != initial.Sub {
		t.Fatal("watcher replaced the already-applied advisor during startup")
	}
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
	go watchConfig(ctx, cfgPath, configWatchDeps{st: store, stk: stk, pub: fleet.NewPublisher(), fleetCfg: &fleetConfigHolder{}})
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

// The watcher swaps the fleet sink set live: enrolling a collector takes
// effect within one poll cycle, unenrolling stops delivery — no restart.
func TestWatchConfigHotSwapsFleet(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	st, err := store.Open(filepath.Join(dir, "e.db"), filepath.Join(dir, "e.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	os.WriteFile(cfgPath, []byte("advisor:\n  enabled: false\n"), 0o600)
	pub := fleet.NewPublisher()
	holder := &fleetConfigHolder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchConfig(ctx, cfgPath, configWatchDeps{
		st: st, stk: &advisorStackHolder{}, pub: pub, fleetCfg: holder, logDir: dir,
	})

	// Baseline: no webhooks.
	time.Sleep(300 * time.Millisecond)
	if pub.HasSinks() {
		t.Fatal("no webhooks configured — publisher must have no sinks")
	}

	// Enroll: a webhook appears in config → sinks live within a poll cycle.
	os.WriteFile(cfgPath, []byte("advisor:\n  enabled: false\nfleet:\n  hostname: builder-01\n  labels: { env: test }\n  heartbeat_interval_sec: 5\n  webhooks:\n    - { url: \"http://127.0.0.1:9999/hooks/secure-agent\", secret: \"s3cret\" }\n"), 0o600)
	waitFor(t, 5*time.Second, pub.HasSinks)
	waitFor(t, 5*time.Second, func() bool {
		fc := holder.Load()
		return fc.Hostname == "builder-01" && fc.Labels["env"] == "test" && fc.HeartbeatIntervalSec == 5
	})

	// Unenroll: webhooks removed → sinks gone.
	os.WriteFile(cfgPath, []byte("advisor:\n  enabled: false\nfleet:\n  webhooks: []\n"), 0o600)
	waitFor(t, 5*time.Second, func() bool { return !pub.HasSinks() })
}

func TestWatchConfigHotSwapsResourcePolicy(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	st, err := store.Open(filepath.Join(dir, "e.db"), filepath.Join(dir, "e.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	controller := resource.NewController(resource.Policy{Mode: resource.ModeObserve}, nil)
	write := func(mode string, rssMB int) {
		src := fmt.Sprintf("resource_control:\n  mode: %s\n  max_rss_mb: %d\n  max_cpu_percent: 150\n  sustain_seconds: 12\n  cooldown_seconds: 60\n", mode, rssMB)
		if err := os.WriteFile(cfgPath, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("prompt", 2048)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchConfig(ctx, cfgPath, configWatchDeps{
		st: st, stk: &advisorStackHolder{}, pub: fleet.NewPublisher(), fleetCfg: &fleetConfigHolder{},
		resourceControl: controller,
	})

	waitFor(t, 5*time.Second, func() bool {
		policy := controller.Snapshot().Control
		return policy != nil && policy.Mode == resource.ModePrompt && policy.MaxRSSBytes == 2048*1024*1024 &&
			policy.MaxCPUPercent == 150 && policy.SustainSeconds == 12 && policy.CooldownSeconds == 60
	})

	write("terminate", 1024)
	waitFor(t, 5*time.Second, func() bool {
		policy := controller.Snapshot().Control
		return policy != nil && policy.Mode == resource.ModeTerminate && policy.MaxRSSBytes == 1024*1024*1024
	})

	src := "resource_control:\n  mode: terminate\n  max_rss_mb: 1024\n  max_cpu_percent: 150\n  sustain_seconds: 12\n  cooldown_seconds: 60\n  workspace_overrides:\n    - cwd_prefix: /work/app\n      mode: prompt\n      max_rss_mb: 4096\n      max_cpu_percent: 200\n      sustain_seconds: 30\n      cooldown_seconds: 300\n"
	if err := os.WriteFile(cfgPath, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool {
		policy := controller.Snapshot().Control
		return policy != nil && len(policy.WorkspaceOverrides) == 1 &&
			policy.WorkspaceOverrides[0].CwdPrefix == "/work/app" &&
			policy.WorkspaceOverrides[0].Mode == resource.ModePrompt
	})
}

// The fleet fingerprint must distinguish every fleet-relevant field — a
// collision would silently skip a real change (e.g. rotating a secret).
func TestFleetConfigKeyDistinguishesFields(t *testing.T) {
	a := config.FleetConfig{
		Hostname: "h1", HeartbeatIntervalSec: 60,
		Labels:   map[string]string{"env": "prod"},
		Webhooks: []config.WebhookConfig{{URL: "http://c", Secret: "s", Events: []string{"flag"}}},
	}
	b := a
	b.Webhooks = []config.WebhookConfig{{URL: "http://c", Secret: "rotated", Events: []string{"flag"}}}
	if fleetConfigKey(a) == fleetConfigKey(b) {
		t.Fatal("key must differ on secret rotation")
	}
	c := a
	c.Labels = map[string]string{"env": "staging"}
	if fleetConfigKey(a) == fleetConfigKey(c) {
		t.Fatal("key must differ on label change")
	}
	d := a
	d.HeartbeatIntervalSec = 30
	if fleetConfigKey(a) == fleetConfigKey(d) {
		t.Fatal("key must differ on interval change")
	}
	// Label map iteration order must not affect the key.
	e := config.FleetConfig{Labels: map[string]string{"a": "1", "b": "2"}}
	f := config.FleetConfig{Labels: map[string]string{"b": "2", "a": "1"}}
	if fleetConfigKey(e) != fleetConfigKey(f) {
		t.Fatal("key must be order-independent for labels")
	}
}
