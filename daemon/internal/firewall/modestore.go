package firewall

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// ModeStore persists per-rule mode overrides (e.g. a rule promoted to block) to
// a small JSON file, so a promotion survives a daemon restart without editing
// the user's config overlay.
type ModeStore struct {
	path string
	mu   sync.Mutex
}

func NewModeStore(path string) *ModeStore {
	return &ModeStore{path: path}
}

// Load returns the persisted rule -> mode overrides. A missing or unreadable
// file yields an empty map (no overrides), never an error.
func (m *ModeStore) Load() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loadLocked()
}

func (m *ModeStore) loadLocked() map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(m.path)
	if err != nil {
		return out
	}
	_ = json.Unmarshal(data, &out)
	return out
}

// Set records rule -> mode and writes the file atomically-ish (0600).
func (m *ModeStore) Set(ruleID, mode string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.loadLocked()
	cur[ruleID] = mode
	if err := os.MkdirAll(filepath.Dir(m.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cur, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.path, data, 0o600)
}
