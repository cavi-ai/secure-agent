package firewall

import (
	"crypto/rand"
	"os"
	"path/filepath"
)

// LoadSalt returns the per-install HMAC salt at path, creating a random 32-byte
// salt (0600) if none exists yet. The salt keeps fingerprints non-portable, so
// it is generated locally and never shipped. If the salt cannot be written, the
// freshly generated in-memory salt is still returned (fail-open).
func LoadSalt(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil && len(b) >= 16 {
		return b, nil
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err == nil {
		_ = os.WriteFile(path, salt, 0o600)
	}
	return salt, nil
}
