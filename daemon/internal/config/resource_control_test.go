package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteResourceControlPreservesAliasesWhenRepairingPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	const original = "# keep defaults\ndefaults: &defaults\n  proxy_enabled: true\n<<: *defaults\nresource_control: broken\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteResourceControl(path, ResourceControlConfig{Mode: "observe"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, preserved := range []string{"# keep defaults", "&defaults", "*defaults"} {
		if !strings.Contains(string(data), preserved) {
			t.Fatalf("lost %q: %s", preserved, data)
		}
	}
	if got, err := LoadStrict(path); err != nil || !got.ProxyEnabled || got.ResourceControl.Mode != "observe" {
		t.Fatalf("repaired policy: %+v, %v", got.ResourceControl, err)
	}
}

func TestWriteResourceControlRejectsInvalidOverlayStructure(t *testing.T) {
	for name, original := range map[string]string{
		"sequence":               "- proxy_enabled: true\n",
		"scalar":                 "keep-me\n",
		"null":                   "null\n",
		"multiple-documents":     "proxy_enabled: true\n---\nfirewall:\n  mode: block\n",
		"invalid-later-document": "proxy_enabled: true\n---\nfirewall: [\n",
		"duplicate-root-key":     "proxy_enabled: true\nproxy_enabled: false\n",
		"duplicate-policy-key":   "resource_control:\n  mode: observe\nresource_control:\n  mode: prompt\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := WriteResourceControl(path, ResourceControlConfig{Mode: "observe"}); err == nil {
				t.Error("invalid overlay was overwritten")
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != original {
				t.Fatalf("overlay changed: %q, %v", got, err)
			}
		})
	}
}

func TestWriteResourceControlAcceptsEmptyOverlay(t *testing.T) {
	for name, original := range map[string]string{"missing": "", "empty": "", "whitespace": " \n\t\n", "comments": "# operator notes\n", "mapping": "{}\n"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if name != "missing" {
				if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := WriteResourceControl(path, ResourceControlConfig{Mode: "observe"}); err != nil {
				t.Fatal(err)
			}
			if got, err := LoadStrict(path); err != nil || got.ResourceControl.Mode != "observe" {
				t.Fatalf("saved policy: %+v, %v", got.ResourceControl, err)
			}
		})
	}
}
