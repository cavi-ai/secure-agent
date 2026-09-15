package main

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Enroll into a node with no config at all: a minimal valid file appears.
func TestMergeFleetWebhookEmptyConfig(t *testing.T) {
	out, err := mergeFleetWebhookYAML(nil, "https://collector:9445/hooks/secure-agent", "abc123")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("merged config is not valid YAML: %v", err)
	}
	fleet := doc["fleet"].(map[string]any)
	hooks := fleet["webhooks"].([]any)
	if len(hooks) != 1 {
		t.Fatalf("webhooks = %v", hooks)
	}
	entry := hooks[0].(map[string]any)
	if entry["url"] != "https://collector:9445/hooks/secure-agent" || entry["secret"] != "abc123" {
		t.Fatalf("entry = %v", entry)
	}
}

// Existing config keeps its other keys and comments; the webhook lands under
// fleet.webhooks without disturbing anything else.
func TestMergeFleetWebhookPreservesExisting(t *testing.T) {
	existing := `# operator config
net_sample_interval_ms: 2000
# advisor stays off for now
advisor:
  enabled: false
fleet:
  hostname: builder-01
`
	out, err := mergeFleetWebhookYAML([]byte(existing), "https://c:1/hooks/secure-agent", "s1")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "net_sample_interval_ms: 2000") ||
		!strings.Contains(s, "# advisor stays off for now") ||
		!strings.Contains(s, "hostname: builder-01") {
		t.Fatalf("existing content lost:\n%s", s)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	hooks := doc["fleet"].(map[string]any)["webhooks"].([]any)
	if len(hooks) != 1 {
		t.Fatalf("webhooks = %v", hooks)
	}
}

// Re-enrolling the same collector rotates the secret IN PLACE — no duplicate
// entries, other webhooks untouched.
func TestMergeFleetWebhookRotatesOnSameURL(t *testing.T) {
	existing := `fleet:
  webhooks:
    - url: https://a:1/hooks/secure-agent
      secret: old-secret
    - url: https://b:2/hooks/secure-agent
      secret: keep-me
`
	out, err := mergeFleetWebhookYAML([]byte(existing), "https://a:1/hooks/secure-agent", "new-secret")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	hooks := doc["fleet"].(map[string]any)["webhooks"].([]any)
	if len(hooks) != 2 {
		t.Fatalf("duplicate entry created: %v", hooks)
	}
	first := hooks[0].(map[string]any)
	second := hooks[1].(map[string]any)
	if first["secret"] != "new-secret" || second["secret"] != "keep-me" {
		t.Fatalf("rotation wrong: %v", hooks)
	}
}

// A malformed existing config must fail loudly — never silently clobber the
// operator's file.
func TestMergeFleetWebhookRejectsMalformed(t *testing.T) {
	if _, err := mergeFleetWebhookYAML([]byte("fleet: [broken\n  man"), "https://c", "s"); err == nil {
		t.Fatal("malformed config must error, not be clobbered")
	}
}

func TestNormalizeCollectorURL(t *testing.T) {
	cases := map[string]string{
		"collector.internal:9445":           "https://collector.internal:9445/hooks/secure-agent",
		"http://127.0.0.1:9445":             "http://127.0.0.1:9445/hooks/secure-agent",
		"https://c:9445/hooks/secure-agent": "https://c:9445/hooks/secure-agent",
		"https://c:9445/":                   "https://c:9445/hooks/secure-agent",
	}
	for in, want := range cases {
		got, err := normalizeCollectorURL(in)
		if err != nil || got != want {
			t.Fatalf("normalize(%q) = %q, %v — want %q", in, got, err, want)
		}
	}
	if _, err := normalizeCollectorURL(""); err == nil {
		t.Fatal("empty URL must error")
	}
}

func TestGenerateSecret(t *testing.T) {
	s, err := generateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 32 {
		t.Fatalf("secret len = %d, want 32 hex chars", len(s))
	}
	other, _ := generateSecret()
	if s == other {
		t.Fatal("secrets must be random")
	}
}
