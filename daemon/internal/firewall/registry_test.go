package firewall

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

func base64Std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestRegistryMatchesRegisteredSecretAcrossEncodings(t *testing.T) {
	salt := []byte("test-salt")
	secret := "s3cr3t-value-abcdefghijklmnop"
	fp := config.Fingerprint{ID: "fp1", Type: TypeEnvValue, Len: len(secret), HMAC: Fingerprint(salt, secret)}
	r := NewRegistry(salt, []config.Fingerprint{fp})

	if got := r.Match([]byte("Authorization: " + secret)); len(got) == 0 || got[0].RuleID != "fp1" {
		t.Fatalf("raw match failed: %+v", got)
	}
	// base64-wrapped occurrence must still match via Normalize
	enc := []byte("blob=" + base64Std(secret))
	if got := r.Match(enc); len(got) == 0 {
		t.Fatal("base64-wrapped secret should match")
	}
}

func TestIngestFingerprintsWithoutStoringPlaintext(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	secret := "STRIPE-abcdef0123456789abcdef01"
	if err := os.WriteFile(envPath, []byte("STRIPE_KEY="+secret+"\n# comment\nEMPTY=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fps, err := Ingest([]string{envPath}, []byte("salt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fps) != 1 {
		t.Fatalf("expected 1 fingerprint, got %d", len(fps))
	}
	if fps[0].HMAC != Fingerprint([]byte("salt"), secret) {
		t.Fatal("fingerprint HMAC mismatch")
	}
	// The struct must not carry the raw secret anywhere.
	if fps[0].Label == secret || fps[0].ID == secret {
		t.Fatal("plaintext secret leaked into fingerprint metadata")
	}
}
