package firewall

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// SourceStore persists the user's runtime-added ingest sources (the files whose
// KEY=VALUE secrets get fingerprinted) so a source added from the console
// survives a restart without editing the config overlay. It mirrors ModeStore
// and FingerprintStore: a small 0600 JSON file next to the salt. It holds paths
// only — never any secret value read from them. Paths are stored raw (a leading
// ~ is expanded at use, not here) so the UI can show what the user typed.
type SourceStore struct {
	path string
	mu   sync.Mutex
}

func NewSourceStore(path string) *SourceStore {
	return &SourceStore{path: path}
}

// Load returns the persisted sources; a missing or unreadable file yields an
// empty slice, never an error.
func (s *SourceStore) Load() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *SourceStore) loadLocked() []string {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil
	}
	var out []string
	if json.Unmarshal(data, &out) != nil {
		return nil
	}
	return out
}

// Add records a source. It returns false without writing when the source is
// already present (add is idempotent).
func (s *SourceStore) Add(src string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.loadLocked()
	for _, existing := range cur {
		if existing == src {
			return false, nil
		}
	}
	return true, s.writeLocked(append(cur, src))
}

// Remove drops a source. It returns false without writing when the source is
// not a user-added source.
func (s *SourceStore) Remove(src string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.loadLocked()
	out := cur[:0:0]
	found := false
	for _, existing := range cur {
		if existing == src {
			found = true
			continue
		}
		out = append(out, existing)
	}
	if !found {
		return false, nil
	}
	return true, s.writeLocked(out)
}

func (s *SourceStore) writeLocked(sources []string) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(sources, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}
