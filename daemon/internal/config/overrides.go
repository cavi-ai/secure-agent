package config

import (
	"encoding/json"
	"fmt"
	"github.com/cavi-ai/secure-agent/daemon/internal/safefile"
	"os"
	"path/filepath"
)

// WriteCwdOverrides renders the hook-readable per-project policy file from
// config. The hook is a stdlib-only Python process and cannot parse YAML, so
// the daemon serializes its parsed view to guard-cwd-overrides.json beside
// its socket (CwdOverridesPath; 0600, user-private). An empty list clears the file
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
	if err := safefile.WriteFileAtomic(path, append(data, '\n'), 0o600); err != nil {
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

// CwdOverridesPath returns where this daemon writes the hook policy file:
// beside its own control socket, so a second daemon (another -config, a test
// run) never rewrites the primary's file. The default socket lives in
// ~/.config/secure-agent/, so the default daemon's path is unchanged.
func CwdOverridesPath(cfg Config) string {
	if cfg.SocketPath == "" {
		return DefaultCwdOverridesPath()
	}
	return filepath.Join(filepath.Dir(cfg.SocketPath), "guard-cwd-overrides.json")
}
