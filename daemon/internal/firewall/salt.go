package firewall

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cavi-ai/secure-agent/daemon/internal/safefile"
)

// LoadSalt returns the per-install HMAC salt at path, creating a random 32-byte
// salt (0600) if none exists yet. The salt keeps fingerprints non-portable, so
// it is generated locally and never shipped.
//
// Rotation is loud, never silent: every fingerprint HMAC was computed under the
// old salt, so minting a new one orphans the entire known-secret registry. A
// file that exists but is unreadable or truncated is therefore an ERROR (the
// operator deletes the file deliberately to rotate), not an excuse to rotate.
func LoadSalt(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		if len(b) >= 16 {
			return b, nil
		}
		return nil, fmt.Errorf("salt file %s is truncated/corrupt (%d bytes); refusing to rotate it silently — every registered fingerprint was HMACed under the old salt. Delete the file deliberately to mint a fresh salt and re-ingest sources", path, len(b))
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("salt file %s exists but is unreadable: %w; refusing to rotate it silently (that would orphan every registered fingerprint)", path, err)
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("salt dir: %w", err)
	}
	if err := safefile.WriteFileAtomic(path, salt, 0o600); err != nil {
		// A salt that only lives in memory would persist this session's ingested
		// HMACs under a salt that is gone on restart — a permanent silent
		// mismatch. Fail instead.
		return nil, fmt.Errorf("persist salt %s: %w", path, err)
	}
	return salt, nil
}
