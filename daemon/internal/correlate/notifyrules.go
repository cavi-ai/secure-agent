package correlate

import (
	"encoding/json"
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
	out := map[string]bool{}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return out
	}
	if err := json.Unmarshal(data, &out); err != nil {
		log.Printf("correlate: WARNING: notify-rules file %s is corrupt (%v); overrides are NOT applied until it is fixed", s.path, err)
		return map[string]bool{}
	}
	return out
}

// Set records an override. Idempotent.
func (s *NotifyRuleStore) Set(rule string, notify bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.loadLocked()
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
	m := s.loadLocked()
	if _, ok := m[rule]; !ok {
		return nil
	}
	delete(m, rule)
	return safefile.WriteFileAtomic(s.path, mustJSON(m), 0o600)
}
