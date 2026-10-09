package daemon

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
)

func TestFirewallRejectsFingerprintOperationsWithoutSalt(t *testing.T) {
	for _, failure := range []string{"truncated", "unreadable"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			saltPath := filepath.Join(dir, "salt")
			salt, err := firewall.LoadSalt(saltPath)
			if err != nil {
				t.Fatal(err)
			}
			const value = "fixture-value-for-fingerprint"
			source := filepath.Join(dir, "fixture.env")
			if err := os.WriteFile(source, []byte("FIXTURE="+value+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			fpPath := filepath.Join(dir, "firewall-fingerprints.json")
			fps := []config.Fingerprint{{ID: "persisted", Type: firewall.TypeEnvValue, Len: len(value), HMAC: firewall.Fingerprint(salt, value)}}
			if err := firewall.NewFingerprintStore(fpPath).Save(fps); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(fpPath)
			if err != nil {
				t.Fatal(err)
			}
			cfg := config.Config{Firewall: config.FirewallConfig{
				Mode:     "block",
				Patterns: []config.PatternConfig{{ID: "typed-rule", Type: firewall.TypeEnvValue, Re: `fixture-pattern-[0-9]+`, Mode: "block"}},
				Registry: config.RegistryConfig{SaltRef: saltPath, IngestSources: []string{source},
					// A previously generated empty-salt HMAC must not keep the
					// fingerprint layer active after a salt-load failure.
					Fingerprints: []config.Fingerprint{{ID: "empty-salt", Type: firewall.TypeEnvValue, Len: len(value), HMAC: firewall.Fingerprint(nil, value)}},
				},
			}}
			if failure == "unreadable" {
				if err := os.Remove(saltPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(saltPath, 0o700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(saltPath, []byte("broken"), 0o600); err != nil {
				t.Fatal(err)
			}
			stack := setupFirewall(cfg)
			if stack.Engine == nil {
				t.Fatal("salt failure disabled the entire firewall")
			}
			if len(stack.Engine.ScanText(value)) != 0 {
				t.Error("fingerprint layer remained active without its salt")
			}
			if err := stack.Reload(); err == nil {
				t.Error("reload accepted an unavailable salt")
			}
			if labels, err := stack.Ingest(); err == nil || len(labels) != 0 {
				t.Errorf("ingest accepted an unavailable salt: %v, %v", labels, err)
			}
			if got, err := os.ReadFile(fpPath); err != nil || !bytes.Equal(got, before) {
				t.Error("failed ingest changed persisted fingerprints")
			}
			if len(stack.Engine.ScanText(value)) != 0 {
				t.Error("failed refresh enabled fingerprints with an empty salt")
			}
			if got := stack.Engine.Inspect(firewall.Request{Agent: "test", Host: "outside.example.com", Body: []byte("fixture-pattern-123")}); got.Action != firewall.ActionBlock {
				t.Errorf("typed detection stopped enforcing: %+v", got)
			}
			if len(cfg.Firewall.Registry.Fingerprints) != 1 {
				t.Fatal("setup mutated the caller's configuration")
			}
			if failure == "unreadable" {
				if info, err := os.Stat(saltPath); err != nil || !info.IsDir() {
					t.Fatal("salt failure was silently replaced")
				}
				if err := os.Remove(saltPath); err != nil {
					t.Fatal(err)
				}
			} else if got, err := os.ReadFile(saltPath); err != nil || string(got) != "broken" {
				t.Fatal("salt failure was silently rotated")
			}
			// The salt is loaded at startup. Restoring it and restarting restores
			// the original persisted HMACs without rotating or re-ingesting them.
			if err := os.WriteFile(saltPath, salt, 0o600); err != nil {
				t.Fatal(err)
			}
			restarted := setupFirewall(cfg)
			if err := restarted.Reload(); err != nil {
				t.Fatal(err)
			}
			if got := restarted.Engine.ScanText(value); len(got) != 1 || got[0].RuleID != "persisted" {
				t.Fatalf("restored salt did not restore detection: %+v", got)
			}
			if _, err := restarted.Ingest(); err != nil {
				t.Fatalf("ingest after restart: %v", err)
			}
		})
	}
}

func TestFirewallReloadPreservesRegistryAfterReadFailure(t *testing.T) {
	for _, failure := range []string{"corrupt", "wrong-type", "unreadable"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			cfg := config.Config{Firewall: config.FirewallConfig{Mode: "block", Registry: config.RegistryConfig{SaltRef: filepath.Join(dir, "salt")}}}
			salt, err := firewall.LoadSalt(cfg.Firewall.Registry.SaltRef)
			if err != nil {
				t.Fatal(err)
			}
			const value = "fixture-value-for-fingerprint"
			path := filepath.Join(dir, "firewall-fingerprints.json")
			fps := []config.Fingerprint{{ID: "persisted", Type: firewall.TypeEnvValue, Len: len(value), HMAC: firewall.Fingerprint(salt, value)}}
			if err := firewall.NewFingerprintStore(path).Save(fps); err != nil {
				t.Fatal(err)
			}
			stack := setupFirewall(cfg)
			if len(stack.Engine.ScanText(value)) != 1 {
				t.Fatal("startup did not load fingerprint")
			}
			if failure == "unreadable" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			} else {
				data := "{broken"
				if failure == "wrong-type" {
					data = `[{"len":"invalid"}]`
				}
				if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := stack.Reload(); err == nil {
				t.Error("reload reported success after read failure")
			}
			if len(stack.Engine.ScanText(value)) != 1 {
				t.Error("failed reload cleared the active registry")
			}
			if failure == "unreadable" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			if err := firewall.NewFingerprintStore(path).Save(fps); err != nil {
				t.Fatal(err)
			}
			if err := stack.Reload(); err != nil {
				t.Fatalf("reload after repair: %v", err)
			}
		})
	}
}

func TestFirewallIngestPreservesRegistryAfterSourcePolicyFailure(t *testing.T) {
	for _, failure := range []string{"corrupt", "null", "unreadable"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			cfg := config.Config{Firewall: config.FirewallConfig{Mode: "block", Registry: config.RegistryConfig{SaltRef: filepath.Join(dir, "salt")}}}
			stack := setupFirewall(cfg)
			const value = "fixture-value-for-fingerprint"
			source := filepath.Join(dir, "fixture.env")
			if err := os.WriteFile(source, []byte("FIXTURE="+value+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := stack.Sources.Add(source); err != nil {
				t.Fatal(err)
			}
			if _, err := stack.Ingest(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "firewall-fingerprints.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			policyPath := filepath.Join(dir, "firewall-sources.json")
			if failure == "unreadable" {
				if err := os.Remove(policyPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(policyPath, 0o700); err != nil {
					t.Fatal(err)
				}
			} else {
				data := "{broken"
				if failure == "null" {
					data = "null"
				}
				if err := os.WriteFile(policyPath, []byte(data), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if labels, err := stack.Ingest(); err == nil || len(labels) != 0 {
				t.Errorf("ingest reported success: %v, %v", labels, err)
			}
			if len(stack.Engine.ScanText(value)) != 1 {
				t.Error("failed ingest cleared active registry")
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != string(before) {
				t.Errorf("failed ingest changed persisted registry: %v", err)
			}
			if failure == "unreadable" {
				if err := os.Remove(policyPath); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(policyPath, []byte(`[]`), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := stack.Sources.Add(source); err != nil {
				t.Fatal(err)
			}
			if _, err := stack.Ingest(); err != nil {
				t.Fatalf("ingest after repair: %v", err)
			}
			if len(stack.Engine.ScanText(value)) != 1 {
				t.Fatal("repaired ingest did not apply registry")
			}
		})
	}
}
