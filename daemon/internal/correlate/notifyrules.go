package correlate

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/cavi-ai/secure-agent/daemon/internal/safefile"
)

// NotifyRuleStore persists per-rule notification overrides: the operator's
// "never page me for this class" / "always page me for this class" choices,
// layered over the default policy (severity >= 3 notifies). A true override
// forces notification even below the severity bar; false suppresses the rule
// entirely. Same file discipline as the other override stores — JSON, 0600,
// atomic, corrupt-file-loud.
type NotifyRuleStore struct {
	path string
	mu   sync.Mutex
}

func NewNotifyRuleStore(path string) *NotifyRuleStore {
	return &NotifyRuleStore{path: path}
}

// Load returns rule -> override (true = always notify, false = never).
func (s *NotifyRuleStore) Load() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *NotifyRuleStore) loadLocked() map[string]bool {
	out, err := readNotifyOverrides(s.path)
	if err != nil {
		log.Printf("correlate: WARNING: cannot load notify-rules (%v); overrides are NOT applied until it is fixed", err)
		return map[string]bool{}
	}
	return out
}

// readNotifyOverrides distinguishes an absent policy from one that cannot be
// loaded. Mutations must never replace unreadable or corrupt operator policy.
func readNotifyOverrides(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read notification policy %s: %w", path, err)
	}
	var out map[string]bool
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("decode notification policy %s: %w", path, err)
	}
	if out == nil {
		return nil, fmt.Errorf("notification policy %s must be a JSON object", path)
	}
	return out, nil
}

// Set records an override. Idempotent.
func (s *NotifyRuleStore) Set(rule string, notify bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := readNotifyOverrides(s.path)
	if err != nil {
		return err
	}
	if cur, ok := m[rule]; ok && cur == notify {
		return nil
	}
	m[rule] = notify
	return safefile.WriteFileAtomic(s.path, mustJSON(m), 0o600)
}

// Clear removes an override, returning the rule to the default policy.
// Clearing an absent rule is a no-op.
func (s *NotifyRuleStore) Clear(rule string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := readNotifyOverrides(s.path)
	if err != nil {
		return err
	}
	if _, ok := m[rule]; !ok {
		return nil
	}
	delete(m, rule)
	return safefile.WriteFileAtomic(s.path, mustJSON(m), 0o600)
}
