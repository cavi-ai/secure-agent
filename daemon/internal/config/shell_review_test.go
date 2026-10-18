package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestShellReviewRejectsUnsafeConfiguration(t *testing.T) {
	for _, body := range []string{
		"enabled: true\n    endpoint: https://example.com",
		"enabled: true\n    endpoint: ''",
		"enabled: true\n    endpoint: http://127.0.0.1:8009\n    timeout_ms: -1",
		"enabled: true\n    endpoint: http://127.0.0.1:8009\n    timeout_ms: 60000",
		"enabled: true\n    endpoint: http://127.0.0.1:8009\n    mode: allow",
	} {
		p := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(p, []byte("directory_guard:\n  shell_review:\n    "+body+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Fatal("unsafe shell review configuration accepted")
		}
	}
}
