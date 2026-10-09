package correlate

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/cavi-ai/secure-agent/daemon/internal/hostid"
	"github.com/cavi-ai/secure-agent/daemon/internal/safefile"
)

// AllowlistStore persists user-added vendor-allowlist hosts (approved from the
// console's egress suggestions) to a small JSON file, so an approval survives
// a daemon restart without editing the config overlay. Same philosophy as the
// firewall ModeStore.
type AllowlistStore struct {
	path string
	mu   sync.Mutex
}

func NewAllowlistStore(path string) *AllowlistStore {
	return &AllowlistStore{path: path}
}

// Load returns agent -> approved hosts. A missing file is empty; a corrupt one
// is a loud empty (approved hosts must never silently revert to uninspected).
func (s *AllowlistStore) Load() map[string][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *AllowlistStore) loadLocked() map[string][]string {
	out, err := s.readLocked()
	if err != nil {
		log.Printf("correlate: WARNING: cannot load allowlist overrides (%v); user-approved hosts are NOT applied until it is fixed", err)
		return map[string][]string{}
	}
	return out
}

// readLocked distinguishes missing policy from failed loads so edits never
// overwrite unreadable or corrupt operator approvals.
func (s *AllowlistStore) readLocked() (map[string][]string, error) {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return map[string][]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read allowlist policy %s: %w", s.path, err)
	}
	var out map[string][]string
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("decode allowlist policy %s: %w", s.path, err)
	}
	if out == nil {
		return nil, fmt.Errorf("allowlist policy %s must be a JSON object", s.path)
	}
	return out, nil
}

// Allows reports whether host is approved for agent, by the same match rule
// the correlator applies to vendor hosts (exact or dot-boundary suffix,
// case-insensitive).
func (s *AllowlistStore) Allows(agent, host string) bool {
	for _, allowed := range s.Load()[agent] {
		if hostid.HostMatches(host, allowed) {
			return true
		}
	}
	return false
}

// Add records host under agent and writes the file atomically (0600).
// Idempotent: adding an existing host is a no-op write.
func (s *AllowlistStore) Add(agent, host string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.readLocked()
	if err != nil {
		return err
	}
	for _, h := range m[agent] {
		if h == host {
			return nil
		}
	}
	m[agent] = append(m[agent], host)
	return safefile.WriteFileAtomic(s.path, mustJSON(m), 0o600)
}

// Remove deletes host from agent's approved set. Every approval must be
// reversible — an allowlist you can only grow is a ratchet, not a policy.
// Idempotent: removing an absent host is a no-op.
func (s *AllowlistStore) Remove(agent, host string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.readLocked()
	if err != nil {
		return err
	}
	hosts := m[agent]
	kept := hosts[:0]
	for _, h := range hosts {
		if h != host {
			kept = append(kept, h)
		}
	}
	if len(kept) == 0 {
		delete(m, agent)
	} else {
		m[agent] = kept
	}
	return safefile.WriteFileAtomic(s.path, mustJSON(m), 0o600)
}

func mustJSON(v any) []byte {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err) // map[string][]string cannot fail to marshal
	}
	return data
}
