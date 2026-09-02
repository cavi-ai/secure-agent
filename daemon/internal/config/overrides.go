package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// WriteCwdOverrides renders the hook-readable per-project policy file from
// config. The hook is a stdlib-only Python process and cannot parse YAML, so
// the daemon serializes its parsed view to ~/.config/secure-agent/
// guard-cwd-overrides.json (0600, user-private). An empty list clears the file
// (the hook then falls back to global modes).
func WriteCwdOverrides(path string, overrides []CwdOverride) error {
	if path == "" {
		return fmt.Errorf("cwd overrides path is empty")
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create overrides dir: %w", err)
		}
	}
	if overrides == nil {
		overrides = []CwdOverride{}
	}
	data, err := json.MarshalIndent(overrides, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write overrides: %w", err)
	}
	return nil
}

// DefaultCwdOverridesPath returns the canonical hook-readable path, sibling of
// the guard-modes override file.
func DefaultCwdOverridesPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "secure-agent", "guard-cwd-overrides.json")
}