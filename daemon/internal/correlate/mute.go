package correlate

import (
	"encoding/json"
	"log"
	"os"
	"sync"

	"github.com/cavi-ai/secure-agent/daemon/internal/safefile"
)

// MuteStore persists operator dispositions: (rule, host) pairs the operator
// has said "stop telling me about" (typically after an advisor-benign
// verdict). Same file discipline as the other override stores — JSON, 0600,
// atomic, corrupt-file-loud.
type MuteStore struct {
	path string
	mu   sync.Mutex
}

func NewMuteStore(path string) *MuteStore {
	return &MuteStore{path: path}
}

// Load returns rule -> muted hosts.
func (s *MuteStore) Load() map[string][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *MuteStore) loadLocked() map[string][]string {
	out := map[string][]string{}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return out
	}
	if err := json.Unmarshal(data, &out); err != nil {
		log.Printf("correlate: WARNING: mute file %s is corrupt (%v); dispositions are NOT applied until it is fixed", s.path, err)
		return map[string][]string{}
	}
	return out
}

// Add records a disposition. Idempotent.
func (s *MuteStore) Add(rule, host string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.loadLocked()
	for _, h := range m[rule] {
		if h == host {
			return nil
		}
	}
	m[rule] = append(m[rule], host)
	return safefile.WriteFileAtomic(s.path, mustJSON(m), 0o600)
}

// Remove deletes one disposition (unmute). Removing an absent pair is a no-op.
func (s *MuteStore) Remove(rule, host string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.loadLocked()
	hosts := m[rule]
	out := hosts[:0]
	for _, h := range hosts {
		if h != host {
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		delete(m, rule)
	} else {
		m[rule] = out
	}
	return safefile.WriteFileAtomic(s.path, mustJSON(m), 0o600)
}
