package sensitive

import (
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

func classifier(t *testing.T) Classifier {
	c, err := config.Load("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	return New(c)
}

func TestClassify(t *testing.T) {
	cl := classifier(t)
	cases := []struct {
		path string
		want bool
	}{
		{"/Users/x/project/.env", true},
		{"/Users/x/project/.env.local", true},
		{"/Users/x/.ssh/id_ed25519", true},
		{"/Users/x/.aws/credentials", true},
		{"/Users/x/Library/Keychains/login.keychain-db", true},
		{"/Users/x/project/main.go", false},
		{"/Users/x/project/README.md", false},
	}
	for _, tc := range cases {
		cat, got := cl.Classify(tc.path)
		if got != tc.want {
			t.Errorf("Classify(%q) sensitive=%v (cat=%v), want %v", tc.path, got, cat, tc.want)
		}
	}
}

// System trust-store reads are normal macOS behavior — they must classify as
// keychain_system_trust, NOT the CRITICAL keychain category.
func TestClassifySystemTrustStore(t *testing.T) {
	c := New(config.Config{KeychainMarkers: []string{"library/keychains", ".keychain-db"}})
	cases := map[string]Category{
		"/System/Library/Keychains/SystemTrustSettings.plist": CatKeychainSystem,
		"/System/Library/Keychains/System.keychain":           CatKeychainSystem,
		"/Users/x/Library/Keychains/login.keychain-db":        CatKeychain,
		"/Users/x/Library/Keychains/data.keychain":            CatKeychain,
	}
	for path, want := range cases {
		got, ok := c.Classify(path)
		if !ok || got != want {
			t.Errorf("Classify(%q) = %v,%v; want %v,true", path, got, ok, want)
		}
	}
}

// A glob with a directory component names one file; only that full path
// matches. Bare-name and "**/" globs match the file name anywhere.
func TestAnchoredGlobsMatchFullPathOnly(t *testing.T) {
	c := New(config.Config{SensitiveGlobs: []string{
		"**/.env",
		"/Users/x/.kube/config",
		"/Users/x/.claude/settings.json",
		"*.keychain-db",
	}})
	cases := []struct {
		path string
		want bool
	}{
		{"/Users/x/.kube/config", true},
		{"/Users/x/proj/config", false},
		{"/Users/x/proj/settings.json", false},
		{"/Users/x/.claude/settings.json", true},
		{"/Users/x/proj/.env", true},
		{"/Users/x/a/b/x.keychain-db", true},
	}
	for _, tc := range cases {
		cat, got := c.Classify(tc.path)
		if got != tc.want {
			t.Errorf("Classify(%q) sensitive=%v (cat=%v), want %v", tc.path, got, cat, tc.want)
		}
	}
}

func TestMatchReportsRule(t *testing.T) {
	c := New(config.Config{
		KeychainMarkers: []string{".keychain-db"},
		SensitiveGlobs:  []string{"/Users/x/.kube/config"},
	})
	cases := map[string]string{
		"/Users/x/proj/.env":                           "env-file",
		"/Users/x/.kube/config":                        "glob:/Users/x/.kube/config",
		"/Users/x/Library/Keychains/login.keychain-db": "keychain:.keychain-db",
		"/Users/x/.ssh/id_ed25519":                     "ssh-key",
	}
	for path, want := range cases {
		m, ok := c.Match(path)
		if !ok || m.Rule != want {
			t.Errorf("Match(%q) = %+v,%v; want rule %q", path, m, ok, want)
		}
	}
}
