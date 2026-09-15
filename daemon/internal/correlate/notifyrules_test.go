package correlate

import (
	"path/filepath"
	"testing"
)

func TestNotifyRuleStoreRoundTrip(t *testing.T) {
	s := NewNotifyRuleStore(filepath.Join(t.TempDir(), "notify-rules.json"))

	if got := s.Load()["keychain-access"]; got != false {
		t.Fatalf("absent rule must read as zero value, got %v", got)
	}
	if err := s.Set("keychain-access", false); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("proxy-secret-leak", true); err != nil {
		t.Fatal(err)
	}
	m := s.Load()
	if v, ok := m["keychain-access"]; !ok || v != false {
		t.Fatalf("stored false override missing: %v", m)
	}
	if v, ok := m["proxy-secret-leak"]; !ok || v != true {
		t.Fatalf("stored true override missing: %v", m)
	}
	// Idempotent set.
	if err := s.Set("proxy-secret-leak", true); err != nil {
		t.Fatal(err)
	}
	// Clear returns the rule to the default policy.
	if err := s.Clear("keychain-access"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Load()["keychain-access"]; ok {
		t.Fatal("cleared override must be gone")
	}
	// Clearing an absent rule is a no-op.
	if err := s.Clear("never-set"); err != nil {
		t.Fatal(err)
	}
	// A false override must survive a reload (bool zero value can't be
	// confused with absent).
	s2 := NewNotifyRuleStore(s.path)
	s2.Set("tcc-tamper", false)
	if v, ok := s2.Load()["tcc-tamper"]; !ok || v != false {
		t.Fatal("false override must round-trip through the file")
	}
}
