package config

import (
	"os"
	"path/filepath"
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
