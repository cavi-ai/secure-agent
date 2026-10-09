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

// Load returns the persisted sources. Failed loads are warned and yield no
// sources; edits must successfully read the existing policy.
func (s *SourceStore) Load() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out, err := s.readLocked()
	if err != nil {
		log.Printf("firewall: WARNING: %v; user-added sources are NOT loaded until it is fixed", err)
		return nil
	}
	return out
}

func (s *SourceStore) readLocked() ([]string, error) {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read firewall ingest sources: %w", err)
	}
	var out []string
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("decode firewall ingest sources %s: %w", s.path, err)
	}
	if out == nil {
		return nil, fmt.Errorf("decode firewall ingest sources %s: expected a JSON array, got null", s.path)
	}
	return out, nil
}

// Add records a source. It returns false without writing when the source is
// already present (add is idempotent).
func (s *SourceStore) Add(src string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.readLocked()
	if err != nil {
		return false, err
	}
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
	cur, err := s.readLocked()
	if err != nil {
		return false, err
	}
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
	return safefile.WriteFileAtomic(s.path, data, 0o600)
}
