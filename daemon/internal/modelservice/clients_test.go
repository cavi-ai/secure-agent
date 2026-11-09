package modelservice

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

func TestClientMigrationKeepsHardenedListenerReachable(t *testing.T) {
	for _, endpoint := range []string{"http://[::1]:19001", "http://127.0.0.2:19001", "http://LOCALHOST:19001"} {
		t.Run(endpoint, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			raw := []byte("advisor:\n  enabled: true\n  endpoint: " + endpoint + "\n  model: fixture\n# retain operator note\n")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			updated, fields, err := clientConfiguration(path, raw, Change{Port: 19001, Scope: "authenticated_inference"}, "/private/model.key")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, updated, 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.LoadStrict(path)
			if err != nil || cfg.Advisor.Endpoint != "http://127.0.0.1:19001" || cfg.Advisor.APIKeyFile != "/private/model.key" {
				t.Fatalf("migrated client cannot use the new listener: %+v err=%v", cfg.Advisor, err)
			}
			if !slices.Contains(fields, "advisor.endpoint") || !slices.Contains(fields, "advisor.api_key_file") || !strings.Contains(string(updated), "# retain operator note") {
				t.Fatal("preview omitted changed endpoint/key fields or lost operator comment")
			}
		})
	}
}

func TestClientMigrationRefusesTLSDowngrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	raw := []byte("advisor:\n  enabled: true\n  endpoint: https://localhost:19001\n  model: fixture\n")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := clientConfiguration(path, raw, Change{Port: 19001, Scope: "authenticated_inference"}, "/private/model.key"); err == nil {
		t.Fatal("HTTP service migration silently accepted a TLS client")
	}
}

func TestBrowserHardeningMigratesOllamaClientsWithoutAddingKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	raw := []byte("advisor:\n  endpoint: http://[::1]:19001\n  classifier_endpoint: http://127.0.0.2:19001\ndirectory_guard:\n  shell_review:\n    endpoint: http://[::1]:19001\nsystem_agent:\n  enabled: true\n  endpoint: http://[::1]:19001\n")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	updated, fields, err := clientConfiguration(path, raw, Change{Port: 19001, Scope: "browser_hardening"}, "/private/unused.key")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, updated, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadStrict(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{cfg.Advisor.Endpoint, cfg.Advisor.ClassifierEndpoint, cfg.DirectoryGuard.ShellReview.Endpoint, cfg.SystemAgent.Endpoint} {
		if endpoint != "http://127.0.0.1:19001" {
			t.Fatalf("client still targets old listener: %s", endpoint)
		}
	}
	if len(fields) != 4 || strings.Contains(string(updated), "unused.key") {
		t.Fatalf("browser hardening added authentication or omitted client endpoints: %v", fields)
	}
}

func TestClientMigrationRefusesAnchoredAndAliasedFields(t *testing.T) {
	for _, raw := range []string{
		"advisor:\n  endpoint: &shared http://[::1]:19001\nother: *shared\n",
		"shared: &shared http://[::1]:19001\nadvisor:\n  endpoint: *shared\n",
		"advisor:\n  endpoint: http://127.0.0.1:19001\n  api_key_file: &shared /private/old.key\nother: *shared\n",
		"advisor: &shared\n  endpoint: http://[::1]:19001\nother: *shared\n",
	} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := clientConfiguration(path, []byte(raw), Change{Port: 19001, Scope: "authenticated_inference"}, "/private/new.key"); err == nil {
			t.Error("automatic migration accepted a shared or aliased configuration field")
		}
	}
}
