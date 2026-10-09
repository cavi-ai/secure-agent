package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
)

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
