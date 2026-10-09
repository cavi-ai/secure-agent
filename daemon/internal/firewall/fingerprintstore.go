package firewall

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/safefile"
)

// FingerprintStore persists the user's registered secret fingerprints (HMAC
// only, never plaintext) so the highest-precision detection layer survives a
// restart and can be populated by the `secure-agent fingerprint` command
// without editing the config overlay.
type FingerprintStore struct {
	path string
	mu   sync.Mutex
}

func NewFingerprintStore(path string) *FingerprintStore {
	return &FingerprintStore{path: path}
}

// Load returns persisted fingerprints, warning and yielding none on failure.
// Live refreshes use LoadStrict to retain the active registry on failure.
func (s *FingerprintStore) Load() []config.Fingerprint {
	out, err := s.LoadStrict()
	if err != nil {
		log.Printf("firewall: WARNING: %v; persisted secret fingerprints are NOT loaded until it is fixed", err)
		return nil
	}
	return out
}

// LoadStrict distinguishes missing state from a failed read or decode. JSON
// null remains a valid empty registry because Save(nil) historically writes it.
func (s *FingerprintStore) LoadStrict() ([]config.Fingerprint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read firewall fingerprints: %w", err)
	}
	var out []config.Fingerprint
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("decode firewall fingerprints %s: %w", s.path, err)
	}
	return out, nil
}

// Save writes the fingerprints (0600). The values themselves are not present —
// each entry carries only an HMAC, type, length, and label.
func (s *FingerprintStore) Save(fps []config.Fingerprint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(fps, "", "  ")
	if err != nil {
		return err
	}
	return safefile.WriteFileAtomic(s.path, data, 0o600)
}
