package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestModelKeyConfigurationLoadsAndRejectsContradictions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := "advisor:\n  api_key_file: /private/model.key\n  classifier_endpoint: http://127.0.0.1:8009\n  classifier_api_key_file: /private/classifier.key\ndirectory_guard:\n  shell_review:\n    api_key_file: /private/shell.key\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadStrict(path)
	if err != nil || cfg.Advisor.APIKeyFile != "/private/model.key" || cfg.Advisor.ClassifierAPIKeyFile != "/private/classifier.key" || cfg.DirectoryGuard.ShellReview.APIKeyFile != "/private/shell.key" {
		t.Fatalf("model credentials config: %+v %v", cfg.Advisor, err)
	}
	for _, change := range []func(*Config){
		func(c *Config) { c.Advisor.APIKeyFile = "relative.key" },
		func(c *Config) { c.Advisor.Managed = true },
		func(c *Config) { c.Advisor.ClassifierEndpoint = "" },
		func(c *Config) { c.DirectoryGuard.ShellReview.APIKeyFile = "relative.key" },
	} {
		c := cfg
		change(&c)
		if err := c.Validate(); err == nil {
			t.Fatal("unsafe or ignored key-file configuration accepted")
		}
	}
}
