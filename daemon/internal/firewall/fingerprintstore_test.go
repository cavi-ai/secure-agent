package firewall

import (
	"path/filepath"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

func TestFingerprintStoreStrictEmptyCompatibility(t *testing.T) {
	s := NewFingerprintStore(filepath.Join(t.TempDir(), "fingerprints.json"))
	if got, err := s.LoadStrict(); err != nil || len(got) != 0 {
		t.Fatalf("missing registry: %v, %v", got, err)
	}
	for _, fps := range [][]config.Fingerprint{nil, {}} {
		if err := s.Save(fps); err != nil {
			t.Fatal(err)
		}
		if got, err := s.LoadStrict(); err != nil || len(got) != 0 {
			t.Fatalf("empty registry: %v, %v", got, err)
		}
	}
}

func TestFingerprintStorePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "firewall-fingerprints.json")
	s := NewFingerprintStore(path)

	if len(s.Load()) != 0 {
		t.Fatal("fresh store should be empty")
	}
	fps := []config.Fingerprint{
		{ID: "fp-1", Type: TypeEnvValue, Len: 20, Label: "STRIPE (~/.env)", HMAC: "abc"},
	}
	if err := s.Save(fps); err != nil {
		t.Fatal(err)
	}

	got := NewFingerprintStore(path).Load()
	if len(got) != 1 || got[0].ID != "fp-1" || got[0].HMAC != "abc" {
		t.Fatalf("persisted fingerprints mismatch: %+v", got)
	}
}
