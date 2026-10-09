package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
)

func TestResourcePolicyUpdaterRejectsInvalidOverlayBeforeApply(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	const original = "proxy_enabled: true\n---\nfirewall:\n  mode: block\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	controller := resource.NewController(resource.Policy{Mode: resource.ModeObserve, MaxRSSBytes: 100}, nil)
	update := buildResourcePolicyUpdater(path, controller)
	next := config.ResourceControlConfig{Mode: "prompt", MaxRSSMB: 2048}
	if err := update(next); err == nil {
		t.Error("invalid overlay update succeeded")
	}
	if got := controller.Snapshot().Control; got.Mode != resource.ModeObserve || got.MaxRSSBytes != 100 {
		t.Errorf("failed write changed active policy: %+v", got)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != original {
		t.Fatalf("overlay changed: %q, %v", got, err)
	}
	// Repairing the file allows the same updater to persist and apply the policy.
	if err := os.WriteFile(path, []byte("proxy_enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := update(next); err != nil {
		t.Fatal(err)
	}
	if got := controller.Snapshot().Control.Mode; got != resource.ModePrompt {
		t.Fatalf("repaired policy was not applied: %v", got)
	}
	if got, err := config.LoadStrict(path); err != nil || !got.ProxyEnabled || got.ResourceControl.Mode != "prompt" {
		t.Fatalf("repaired overlay: %+v, %v", got.ResourceControl, err)
	}
}
