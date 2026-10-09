package daemon

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
)

func TestFirewallIngestPreservesRegistryWhenSourceBecomesDevice(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "fixture.env")
	const value = "original-fixture-value"
	const replacement = "replacement-fixture-value"
	if err := os.WriteFile(source, []byte("FIXTURE="+value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stack := setupFirewall(config.Config{Firewall: config.FirewallConfig{
		Mode:     "block",
		Registry: config.RegistryConfig{SaltRef: filepath.Join(dir, "salt")},
	}})
	if stack.Engine == nil {
		t.Fatal("engine initialization failed")
	}
	if _, err := stack.Sources.Add(source); err != nil {
		t.Fatal(err)
	}
	if labels, err := stack.Ingest(); err != nil || len(labels) != 1 {
		t.Fatalf("initial ingestion: %v, %v", labels, err)
	}
	path := filepath.Join(dir, "firewall-fingerprints.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(os.DevNull, source); err != nil {
		t.Fatal(err)
	}
	if labels, err := stack.Ingest(); err == nil || len(labels) != 0 {
		t.Errorf("device ingestion succeeded: %v, %v", labels, err)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, before) {
		t.Error("device ingestion changed persisted fingerprints")
	}
	if len(stack.Engine.ScanText(value)) != 1 {
		t.Error("device ingestion removed active detection")
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("FIXTURE="+replacement+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if labels, err := stack.Ingest(); err != nil || len(labels) != 1 {
		t.Fatalf("repaired source ingestion: %v, %v", labels, err)
	}
	if len(stack.Engine.ScanText(replacement)) != 1 || len(stack.Engine.ScanText(value)) != 0 {
		t.Fatal("repaired source did not replace active fingerprints")
	}
}

func TestFirewallIngestPreservesRegistryOnPartialScan(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "fixture.env")
	const first = "first-fixture-value"
	const second = "second-fixture-value"
	const replacement = "replacement-fixture-value"
	valid := "FIRST=" + first + "\nSECOND=" + second + "\n"
	if err := os.WriteFile(source, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	stack := setupFirewall(config.Config{Firewall: config.FirewallConfig{
		Mode:     "block",
		Registry: config.RegistryConfig{SaltRef: filepath.Join(dir, "salt"), IngestSources: []string{source}},
	}})
	if stack.Engine == nil {
		t.Fatal("engine initialization failed")
	}
	if labels, err := stack.Ingest(); err != nil || len(labels) != 2 {
		t.Fatalf("initial ingestion: %v, %v", labels, err)
	}
	path := filepath.Join(dir, "firewall-fingerprints.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	broken := "FIRST=" + first + "\n#" + strings.Repeat("x", 1<<20) + "\nSECOND=" + second + "\n"
	if err := os.WriteFile(source, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	if labels, err := stack.Ingest(); err == nil || len(labels) != 0 {
		t.Errorf("partial ingestion succeeded: %v, %v", labels, err)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, before) {
		t.Error("partial ingestion changed persisted fingerprints")
	}
	for _, value := range []string{first, second} {
		if len(stack.Engine.ScanText(value)) != 1 {
			t.Errorf("partial ingestion removed detection for %q", value)
		}
	}
	if err := os.WriteFile(source, []byte("REPLACEMENT="+replacement+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if labels, err := stack.Ingest(); err != nil || len(labels) != 1 {
		t.Fatalf("repaired source ingestion: %v, %v", labels, err)
	}
	if len(stack.Engine.ScanText(replacement)) != 1 || len(stack.Engine.ScanText(first)) != 0 || len(stack.Engine.ScanText(second)) != 0 {
		t.Fatal("repaired source did not replace live fingerprints")
	}
	salt, err := firewall.LoadSalt(filepath.Join(dir, "salt"))
	if err != nil {
		t.Fatal(err)
	}
	if fps, err := firewall.NewFingerprintStore(path).LoadStrict(); err != nil || len(fps) != 1 || fps[0].HMAC != firewall.Fingerprint(salt, replacement) {
		t.Fatalf("repaired source fingerprints not persisted: %+v, %v", fps, err)
	}
}

func TestFirewallRejectsFingerprintOperationsWithoutEngine(t *testing.T) {
	dir := t.TempDir()
	saltPath := filepath.Join(dir, "salt")
	salt, err := firewall.LoadSalt(saltPath)
	if err != nil {
		t.Fatal(err)
	}
	const originalValue = "previous-fixture-value"
	const nextValue = "new-fixture-value"
	path := filepath.Join(dir, "firewall-fingerprints.json")
	fps := []config.Fingerprint{{ID: "persisted", Type: firewall.TypeEnvValue, Len: len(originalValue), HMAC: firewall.Fingerprint(salt, originalValue)}}
	if err := firewall.NewFingerprintStore(path).Save(fps); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "fixture.env")
	if err := os.WriteFile(source, []byte("FIXTURE="+nextValue+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Firewall: config.FirewallConfig{
		Mode:     "block",
		Patterns: []config.PatternConfig{{ID: "broken-rule", Re: "[", Mode: "block"}},
		Registry: config.RegistryConfig{SaltRef: saltPath, IngestSources: []string{source}},
	}}
	stack := setupFirewall(cfg)
	if stack.Engine != nil {
		t.Fatal("invalid pattern unexpectedly built an engine")
	}
	if err := stack.Reload(); err == nil || !strings.Contains(err.Error(), "broken-rule") {
		t.Errorf("reload did not report initialization failure: %v", err)
	}
	if labels, err := stack.Ingest(); err == nil || len(labels) != 0 || !strings.Contains(err.Error(), "broken-rule") {
		t.Errorf("ingest did not report initialization failure: %v, %v", labels, err)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, before) {
		t.Fatal("failed ingest replaced persisted fingerprints")
	}
	// Correcting the pattern and restarting restores the preserved registry
	// and allows a new successful ingestion to replace it.
	cfg.Firewall.Patterns[0].Re = `fixture-pattern-[0-9]+`
	restarted := setupFirewall(cfg)
	if restarted.Engine == nil {
		t.Fatal("repaired pattern did not build an engine")
	}
	if got := restarted.Engine.ScanText(originalValue); len(got) != 1 || got[0].RuleID != "persisted" {
		t.Fatalf("preserved registry was not restored: %+v", got)
	}
	if err := restarted.Reload(); err != nil {
		t.Fatal(err)
	}
	if labels, err := restarted.Ingest(); err != nil || len(labels) != 1 {
		t.Fatalf("ingest after restart: %v, %v", labels, err)
	}
	if len(restarted.Engine.ScanText(nextValue)) != 1 || len(restarted.Engine.ScanText(originalValue)) != 0 {
		t.Fatal("successful ingest did not replace the live registry")
	}
	if got, err := firewall.NewFingerprintStore(path).LoadStrict(); err != nil || len(got) != 1 || got[0].HMAC != firewall.Fingerprint(salt, nextValue) {
		t.Fatalf("successful ingest not persisted: %+v, %v", got, err)
	}
}

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
