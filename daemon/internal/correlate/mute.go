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
// verdict), optionally scoped to one agent. Same file discipline as the
// other override stores — JSON, 0600, atomic, corrupt-file-loud.
type MuteStore struct {
	path string
	mu   sync.Mutex
}

// Mute is one muted host of a rule. An empty Agent mutes the pair for every
// agent. On disk an every-agent mute is the bare host string (the format
// before per-agent mutes); a scoped one is {"host","agent"}.
type Mute struct {
	Host  string `json:"host"`
	Agent string `json:"agent,omitempty"`
}

// Matches reports whether this mute covers host for agent.
func (m Mute) Matches(host, agent string) bool {
	return (m.Host == host || m.Host == "*") && (m.Agent == "" || m.Agent == agent)
}

func (m Mute) MarshalJSON() ([]byte, error) {
	if m.Agent == "" {
		return json.Marshal(m.Host)
	}
	type plain Mute
	return json.Marshal(plain(m))
}

func (m *Mute) UnmarshalJSON(b []byte) error {
	var host string
	if err := json.Unmarshal(b, &host); err == nil {
		*m = Mute{Host: host}
		return nil
	}
	type plain Mute
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	*m = Mute(p)
	return nil
}

func NewMuteStore(path string) *MuteStore {
	return &MuteStore{path: path}
}

// Load returns rule -> muted hosts.
func (s *MuteStore) Load() map[string][]Mute {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

// Muted reports whether a mute covers (rule, host) for agent.
func (s *MuteStore) Muted(rule, host, agent string) bool {
	for _, m := range s.Load()[rule] {
		if m.Matches(host, agent) {
			return true
		}
	}
	return false
}

func (s *MuteStore) loadLocked() map[string][]Mute {
	out := map[string][]Mute{}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return out
	}
	if err := json.Unmarshal(data, &out); err != nil {
		log.Printf("correlate: WARNING: mute file %s is corrupt (%v); dispositions are NOT applied until it is fixed", s.path, err)
		return map[string][]Mute{}
	}
	return out
}

// Add records a disposition; an empty agent mutes every agent. Idempotent.
func (s *MuteStore) Add(rule, host, agent string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.loadLocked()
	want := Mute{Host: host, Agent: agent}
	for _, e := range m[rule] {
		if e == want {
			return nil
		}
	}
	m[rule] = append(m[rule], want)
	return safefile.WriteFileAtomic(s.path, mustJSON(m), 0o600)
}

// Remove deletes one disposition (unmute). Removing an absent entry is a no-op.
func (s *MuteStore) Remove(rule, host, agent string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.loadLocked()
	drop := Mute{Host: host, Agent: agent}
	entries := m[rule]
	out := entries[:0]
	for _, e := range entries {
		if e != drop {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		delete(m, rule)
	} else {
		m[rule] = out
	}
	return safefile.WriteFileAtomic(s.path, mustJSON(m), 0o600)
}
