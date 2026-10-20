package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileTelemetryChoicePreservesDiscoveryUntilExplicitlyConfigured(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg, err := LoadStrict(path)
	if err != nil || !cfg.FileTelemetryOn() {
		t.Fatalf("legacy discovery changed: %v", err)
	}
	for _, enabled := range []bool{false, true} {
		value := "false"
		if enabled {
			value = "true"
		}
		if err := os.WriteFile(path, []byte("file_telemetry_enabled: "+value+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		cfg, err = LoadStrict(path)
		if err != nil || cfg.FileTelemetryEnabled == nil || cfg.FileTelemetryOn() != enabled {
			t.Fatalf("choice was not preserved: %+v, %v", cfg.FileTelemetryEnabled, err)
		}
	}
}
