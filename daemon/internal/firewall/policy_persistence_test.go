package firewall

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFirewallPolicyEditsPreserveFailedLoads(t *testing.T) {
	for _, operation := range []string{"mode", "source-add", "source-remove"} {
		for name, data := range map[string]string{"corrupt": `{broken`, "null": `null`, "wrong-type": `42`, "unreadable": ""} {
			t.Run(operation+"/"+name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "policy.json")
				if name == "unreadable" {
					if err := os.Mkdir(path, 0o700); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
					t.Fatal(err)
				}
				var err error
				switch operation {
				case "mode":
					s := NewModeStore(path)
					if len(s.Load()) != 0 {
						t.Fatal("failed load applied overrides")
					}
					err = s.Set("aws-key", "block")
				default:
					s := NewSourceStore(path)
					if len(s.Load()) != 0 {
						t.Fatal("failed load applied sources")
					}
					var changed bool
					if operation == "source-add" {
						changed, err = s.Add("/project/.env")
					} else {
						changed, err = s.Remove("/project/.env")
					}
					if changed {
						t.Fatal("failed edit reported a change")
					}
				}
				if err == nil {
					t.Fatal("edit succeeded after failed load")
				}
				if name == "unreadable" {
					if info, err := os.Stat(path); err != nil || !info.IsDir() {
						t.Fatalf("policy directory changed: %v", err)
					}
				} else if got, err := os.ReadFile(path); err != nil || string(got) != data {
					t.Fatalf("policy changed: %q, %v", got, err)
				}
			})
		}
	}
}

func TestFirewallPolicyEditsAfterRepairPreserveExistingEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	modes := NewModeStore(path)
	modes.Load()
	if err := os.WriteFile(path, []byte(`{"aws-key":"block"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := modes.Set("openai-key", "monitor"); err != nil {
		t.Fatal(err)
	}
	if got := NewModeStore(path).Load(); len(got) != 2 || got["aws-key"] != "block" || got["openai-key"] != "monitor" {
		t.Fatalf("repaired modes lost: %v", got)
	}
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	sources := NewSourceStore(path)
	sources.Load()
	if err := os.WriteFile(path, []byte(`["/project/old.env"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if added, err := sources.Add("/project/new.env"); !added || err != nil {
		t.Fatalf("add after repair: %v, %v", added, err)
	}
	if got := NewSourceStore(path).Load(); len(got) != 2 || got[0] != "/project/old.env" || got[1] != "/project/new.env" {
		t.Fatalf("repaired sources lost: %v", got)
	}
}
