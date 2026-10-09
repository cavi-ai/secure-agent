package firewall

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/cavi-ai/secure-agent/daemon/internal/safefile"
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

// Load returns the persisted rule -> mode overrides. Failed loads are warned
// and yield no overrides; edits must successfully read the existing policy.
func (m *ModeStore) Load() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out, err := m.readLocked()
	if err != nil {
		log.Printf("firewall: WARNING: %v; rule block-promotions are NOT applied until it is fixed", err)
		return map[string]string{}
	}
	return out
}

func (m *ModeStore) readLocked() (map[string]string, error) {
	out := map[string]string{}
	data, err := os.ReadFile(m.path)
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read firewall mode overrides: %w", err)
	}
	// A present-but-corrupt file is a security signal, not a silent "no
	// overrides": every rule promoted to block would revert to monitor. Surface
	// it loudly instead of quietly disabling enforcement.
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("decode firewall mode overrides %s: %w", m.path, err)
	}
	if out == nil {
		return nil, fmt.Errorf("decode firewall mode overrides %s: expected a JSON object, got null", m.path)
	}
	return out, nil
}

// Set records rule -> mode and writes the file atomically (0600).
func (m *ModeStore) Set(ruleID, mode string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, err := m.readLocked()
	if err != nil {
		return err
	}
	cur[ruleID] = mode
	if err := os.MkdirAll(filepath.Dir(m.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cur, "", "  ")
	if err != nil {
		return err
	}
	return safefile.WriteFileAtomic(m.path, data, 0o600)
}
