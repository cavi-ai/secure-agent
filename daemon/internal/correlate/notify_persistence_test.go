package correlate

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestNotifyMutationsPreserveInvalidFiles(t *testing.T) {
	for _, scope := range []bool{false, true} {
		name := "rule"
		if scope {
			name = "workspace"
		}
		t.Run(name, func(t *testing.T) {
			for _, content := range []string{`{"existing":false,`, `null`, `{"existing":"invalid"}`} {
				for _, operation := range []string{"set", "clear"} {
					t.Run(content+"/"+operation, func(t *testing.T) {
						path := filepath.Join(t.TempDir(), "notify.json")
						if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
							t.Fatal(err)
						}
						var err error
						if scope {
							s := NewNotifyScopeStore(path)
							if operation == "set" {
								err = s.Set("/repo", "proxy-secret-leak", true)
							} else {
								err = s.Clear("/repo", "proxy-secret-leak")
							}
						} else {
							s := NewNotifyRuleStore(path)
							if operation == "set" {
								err = s.Set("proxy-secret-leak", true)
							} else {
								err = s.Clear("proxy-secret-leak")
							}
						}
						if err == nil {
							t.Error("mutation of invalid policy must fail")
						}
						got, readErr := os.ReadFile(path)
						if readErr != nil {
							t.Fatal(readErr)
						}
						if !bytes.Equal(got, []byte(content)) {
							t.Fatalf("invalid policy overwritten: got %q, want %q", got, content)
						}
					})
				}
			}
		})
	}
}

func TestNotifyMutationsReportReadErrors(t *testing.T) {
	// A directory produces a real read error even when tests run as root.
	path := t.TempDir()
	rules := NewNotifyRuleStore(path)
	scopes := NewNotifyScopeStore(path)
	for name, mutate := range map[string]func() error{
		"rule set":    func() error { return rules.Set("proxy-secret-leak", true) },
		"rule clear":  func() error { return rules.Clear("proxy-secret-leak") },
		"scope set":   func() error { return scopes.Set("/repo", "proxy-secret-leak", true) },
		"scope clear": func() error { return scopes.Clear("/repo", "proxy-secret-leak") },
	} {
		t.Run(name, func(t *testing.T) {
			if err := mutate(); err == nil {
				t.Fatal("read failure must be returned to the caller")
			}
		})
	}
}
