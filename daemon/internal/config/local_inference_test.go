package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLocalInferenceDefaultsAndValidation(t *testing.T) {
	cfg, err := LoadStrict(filepath.Join(t.TempDir(),"missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.LocalInference.Enabled || len(cfg.LocalInference.Gateways) != 0 {
		t.Fatal("monitoring should default on without opening a gateway")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("local_inference:\n  enabled: false\n  gateways:\n    - listen: 0.0.0.0:11435\n      upstream: http://127.0.0.1:11434\n      api_key_file: /private/gateway.key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStrict(path); err == nil {
		t.Fatal("wildcard gateway accepted")
	}
	if err := os.WriteFile(path, []byte("local_inference:\n  enabled: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	disabled, err := LoadStrict(path)
	if err != nil || disabled.LocalInference.Enabled {
		t.Fatalf("cannot disable monitor: %v", err)
	}
	if got := RestartSettings(cfg, disabled); len(got) != 1 || got[0] != "local_inference" {
		t.Fatalf("restart: %v", got)
	}
}
