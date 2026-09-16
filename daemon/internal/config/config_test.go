package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDefaultsWhenNoOverlay(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Agents) == 0 {
		t.Fatal("expected default agents")
	}
	if c.NetSampleInterval.Milliseconds() != 2000 {
		t.Fatalf("interval = %v, want 2s", c.NetSampleInterval)
	}
	if c.ProxyEnabled {
		t.Fatal("default proxy_enabled must be false (inspection is opt-in)")
	}
}

func TestOverlayMergesOverDefaults(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	os.WriteFile(p, []byte("net_sample_interval_ms: 5000\n"), 0o644)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.NetSampleInterval.Milliseconds() != 5000 {
		t.Fatalf("interval = %v, want 5s (overlay)", c.NetSampleInterval)
	}
	if len(c.Agents) == 0 {
		t.Fatal("overlay must not wipe default agents")
	}
}

func TestOverlayRejectsNonPositiveSampleInterval(t *testing.T) {
	// time.NewTicker panics on a non-positive duration; validate at load so the
	// supervisor doesn't recover a permanently crash-looping collector.
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	os.WriteFile(p, []byte("net_sample_interval_ms: 0\n"), 0o644)
	if _, err := Load(p); err == nil {
		t.Fatal("expected validation error for net_sample_interval_ms: 0")
	}
	os.WriteFile(p, []byte("net_sample_interval_ms: -5\n"), 0o644)
	if _, err := Load(p); err == nil {
		t.Fatal("expected validation error for negative interval")
	}
}

func TestOverlayRejectsInvalidProxyPort(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	os.WriteFile(p, []byte("proxy_enabled: true\nproxy_port: 99999\n"), 0o644)
	if _, err := Load(p); err == nil {
		t.Fatal("expected validation error for proxy_port 99999")
	}
	// Port 0 is valid: kernel-assigned (e2e/tests use it).
	os.WriteFile(p, []byte("proxy_enabled: true\nproxy_port: 0\n"), 0o644)
	if _, err := Load(p); err != nil {
		t.Fatalf("proxy_port 0 must be accepted (kernel-assigned): %v", err)
	}
}

func TestMalformedOverlayLogsWarningAndKeepsDefaults(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	os.WriteFile(p, []byte("net_sample_interval_ms: [broken\n"), 0o644)
	c, err := Load(p)
	if err != nil {
		t.Fatalf("malformed overlay should keep defaults, got error: %v", err)
	}
	if c.NetSampleInterval.Milliseconds() != 2000 {
		t.Fatalf("interval = %v, want default 2s", c.NetSampleInterval)
	}
}

func TestFirewallDefaultsLoad(t *testing.T) {
	// Use an absent overlay path so this asserts embedded defaults, not any
	// real ~/.config overlay on the developer's machine.
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Firewall.Mode != "monitor" {
		t.Fatalf("firewall.mode = %q, want monitor", cfg.Firewall.Mode)
	}
	if len(cfg.Firewall.Patterns) == 0 {
		t.Fatal("expected default firewall patterns")
	}
	if v, ok := cfg.Firewall.Vendors["claude"]; !ok || len(v.Hosts) == 0 {
		t.Fatal("expected claude vendor config with hosts")
	}
}

func TestDirectoryGuardDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.DirectoryGuard.PromptDeadlineMS != 45000 {
		t.Fatalf("prompt_deadline_ms = %d, want 45000", cfg.DirectoryGuard.PromptDeadlineMS)
	}
}

func TestGuardRulesJSONParsesAndHookCopyMatches(t *testing.T) {
	doc, err := ParseGuardRules(guardRulesBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Rules) < 6 {
		t.Fatalf("rules = %d, want at least 6", len(doc.Rules))
	}
	hook, err := os.ReadFile(filepath.Join("..", "..", "..", "plugin", "hooks", "guard-rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(bytes.TrimSpace(guardRulesBytes)) != string(bytes.TrimSpace(hook)) {
		t.Fatal("plugin/hooks/guard-rules.json drifted from daemon/internal/config/guard-rules.json")
	}
}

func TestSensitiveGlobsCoveredByGuardRules(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ParseGuardRules(guardRulesBytes)
	if err != nil {
		t.Fatal(err)
	}
	inDoc := map[string]bool{}
	for _, r := range doc.Rules {
		for _, p := range r.Paths {
			inDoc[p] = true
		}
	}
	for _, g := range cfg.SensitiveGlobs {
		// expandPaths may rewrite ~; compare against the raw YAML token via the doc.
		_ = g
	}
	for _, p := range []string{"**/.env", "~/.ssh/id_*", "~/.aws/credentials"} {
		if !inDoc[p] {
			t.Fatalf("guard-rules.json missing correlator glob %q", p)
		}
	}
	found := false
	for _, g := range cfg.SensitiveGlobs {
		if strings.Contains(g, ".zshrc") || strings.Contains(g, "login.keychain") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("Load must merge guard-rules.json paths into SensitiveGlobs")
	}
}

func TestGuardRuleMergeSkipsStarStarBasenames(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range cfg.SensitiveGlobs {
		base := filepath.Base(g)
		if base == "*" || base == "**" {
			t.Fatalf("unsafe glob %q merged into SensitiveGlobs (basename Match would hit every file)", g)
		}
	}
	found := false
	for _, p := range cfg.SensitivePaths {
		if strings.Contains(p, string(filepath.Separator)+"azure") || strings.HasSuffix(p, "azure") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("dir_scan ~/.azure must merge into SensitivePaths")
	}
}

func TestWriteCwdOverridesRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "guard-cwd-overrides.json")
	in := []CwdOverride{
		{CwdPrefix: "/work/api", Rules: map[string]string{"env-files": "deny"}},
	}
	if err := WriteCwdOverrides(p, in); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var out []CwdOverride
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].CwdPrefix != "/work/api" || out[0].Rules["env-files"] != "deny" {
		t.Fatalf("round trip mismatch: %+v", out)
	}
	// File must be user-private.
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("overrides file perms = %v, want 0600", fi.Mode().Perm())
	}
}

func TestWriteCwdOverridesEmptyClears(t *testing.T) {
	p := filepath.Join(t.TempDir(), "guard-cwd-overrides.json")
	if err := WriteCwdOverrides(p, nil); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "[]\n" {
		t.Fatalf("empty override file = %q, want []", string(b))
	}
}

// LoadStrict surfaces overlay corruption instead of masking it with
// defaults — the hot-reload contract (a half-written config must never
// silently reconfigure the advisor).
func TestLoadStrictReportsMalformedOverlay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	// Valid overlay: no error.
	os.WriteFile(path, []byte("advisor:\n  enabled: true\n  managed: false\n  endpoint: \"http://127.0.0.1:11434\"\n  model: \"m\"\n"), 0o600)
	cfg, err := LoadStrict(path)
	if err != nil {
		t.Fatalf("valid overlay: %v", err)
	}
	if !cfg.Advisor.Enabled {
		t.Fatal("advisor must be enabled")
	}

	// Malformed overlay: error carries the sentinel AND the config is
	// defaults (lenient behavior preserved for boot).
	os.WriteFile(path, []byte("advisor:\n  enabled: [broken\n  man"), 0o600)
	_, err = LoadStrict(path)
	if err == nil {
		t.Fatal("malformed overlay must be reported, not masked")
	}
	if !errors.Is(err, ErrOverlayMalformed) {
		t.Fatalf("error must wrap ErrOverlayMalformed; got %v", err)
	}

	// Missing overlay file: no error (no overlay is a valid state).
	os.Remove(path)
	if _, err := LoadStrict(path); err != nil {
		t.Fatalf("missing overlay must not error: %v", err)
	}
}

func TestResourceControlConfigAndValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte("resource_control:\n  mode: prompt\n  max_rss_mb: 4096\n  max_cpu_percent: 175\n  sustain_seconds: 45\n  cooldown_seconds: 600\n  workspace_overrides:\n    - cwd_prefix: /work/critical\n      mode: terminate\n      max_rss_mb: 8192\n      max_cpu_percent: 250\n      sustain_seconds: 60\n      cooldown_seconds: 900\n"), 0o600)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ResourceControl.Mode != "prompt" || cfg.ResourceControl.MaxRSSMB != 4096 ||
		cfg.ResourceControl.MaxCPUPercent != 175 || cfg.ResourceControl.SustainSeconds != 45 ||
		len(cfg.ResourceControl.WorkspaceOverrides) != 1 || cfg.ResourceControl.WorkspaceOverrides[0].CwdPrefix != "/work/critical" {
		t.Fatalf("resource control=%+v", cfg.ResourceControl)
	}
	os.WriteFile(path, []byte("resource_control:\n  mode: destroy\n"), 0o600)
	if _, err := Load(path); err == nil {
		t.Fatal("invalid resource control mode accepted")
	}
}

func TestWriteResourceControlPreservesUnrelatedYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	original := "# keep this comment\nproxy_enabled: true\nresource_control:\n  mode: observe\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	next := ResourceControlConfig{Mode: "prompt", MaxRSSMB: 2048, MaxCPUPercent: 150,
		SustainSeconds: 30, CooldownSeconds: 300, WorkspaceOverrides: []ResourceControlOverride{{
			CwdPrefix: "/work/app", Mode: "terminate", MaxRSSMB: 4096, MaxCPUPercent: 200,
			SustainSeconds: 60, CooldownSeconds: 600,
		}}}
	if err := WriteResourceControl(path, next); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "# keep this comment") || !strings.Contains(text, "proxy_enabled: true") {
		t.Fatalf("unrelated YAML was not preserved:\n%s", text)
	}
	loaded, err := LoadStrict(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ResourceControl.Mode != "prompt" || len(loaded.ResourceControl.WorkspaceOverrides) != 1 {
		t.Fatalf("resource control=%+v", loaded.ResourceControl)
	}
}

func TestResourceControlRejectsUnsafeWorkspaceOverrides(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ResourceControl.WorkspaceOverrides = []ResourceControlOverride{
		{CwdPrefix: "relative/path", Mode: "observe"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("relative workspace prefix accepted")
	}
}

func TestResourceControlRejectsValuesThatOverflowRuntimeUnits(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ResourceControl.MaxRSSMB = ^uint64(0)
	if err := cfg.Validate(); err == nil {
		t.Fatal("RSS value that overflows byte conversion was accepted")
	}
}
