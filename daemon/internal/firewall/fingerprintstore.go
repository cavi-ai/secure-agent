package firewall

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
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

// Load returns the persisted fingerprints; a missing or unreadable file yields
// an empty slice, never an error.
func (s *FingerprintStore) Load() []config.Fingerprint {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil
	}
	var out []config.Fingerprint
	if err := json.Unmarshal(data, &out); err != nil {
		log.Printf("firewall: WARNING: fingerprint file %s is corrupt (%v); persisted secret fingerprints are NOT loaded until it is fixed", s.path, err)
		return nil
	}
	return out
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
	return os.WriteFile(s.path, data, 0o600)
}
