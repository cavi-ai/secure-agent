package main

// `secure-agent fleet enroll <collector-url>` — one-command node onboarding.
// Previously: boot the daemon, hunt down the random node id, invent a secret,
// edit config.yaml by hand, restart the daemon, then edit the collector's
// secrets file by hand. Enroll collapses the node side to one command: it
// reads the node id from the running daemon, generates the secret, merges
// the webhook into config.yaml (comment-preserving, with a backup), and
// prints the single line the collector needs. The daemon's config watcher
// picks the new webhook up within one poll cycle — no restart.

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func handleFleetEnroll(client *http.Client, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: secure-agent fleet enroll <collector-url>")
		fmt.Println("Example: secure-agent fleet enroll https://collector.internal:9445")
		os.Exit(1)
	}
	hookURL, err := normalizeCollectorURL(args[0])
	if err != nil {
		fmt.Printf("enroll: %v\n", err)
		os.Exit(1)
	}

	// 1. Node identity comes from the running daemon — the operator should
	// never have to hunt the random id down in a state directory.
	resp, err := client.Get("http://unix/fleet")
	if err != nil {
		fmt.Printf("enroll: daemon unreachable (%v) — is Secure Agent running?\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var node struct {
		NodeID string `json:"node_id"`
	}
	if err := json.Unmarshal(body, &node); err != nil || node.NodeID == "" {
		fmt.Println("enroll: daemon did not report a node_id — is it running a current version?")
		os.Exit(1)
	}

	// 2. One shared secret per (node, collector) pair, generated here so it
	// is never something an operator invented on a sticky note.
	secret, err := generateSecret()
	if err != nil {
		fmt.Printf("enroll: %v\n", err)
		os.Exit(1)
	}

	// 3. Merge the webhook into the node config (backup first).
	cfgPath := fleetEnrollConfigPath()
	existing, readErr := os.ReadFile(cfgPath)
	existed := readErr == nil
	if readErr != nil && !os.IsNotExist(readErr) {
		fmt.Printf("enroll: cannot read %s: %v\n", cfgPath, readErr)
		os.Exit(1)
	}
	merged, err := mergeFleetWebhookYAML(existing, hookURL, secret)
	if err != nil {
		fmt.Printf("enroll: %v\n", err)
		os.Exit(1)
	}
	if existed {
		if err := os.WriteFile(cfgPath+".bak", existing, 0o600); err != nil {
			fmt.Printf("enroll: backup failed: %v\n", err)
			os.Exit(1)
		}
	}
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		fmt.Printf("enroll: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(cfgPath, merged, 0o600); err != nil {
		fmt.Printf("enroll: write %s: %v\n", cfgPath, err)
		os.Exit(1)
	}

	// 4. What remains is exactly one line on the collector side.
	fmt.Println("Node enrolled.")
	fmt.Println()
	fmt.Println("1) Collector — append this line to its secrets file, then restart the collector:")
	fmt.Printf("   %s=%s\n", node.NodeID, secret)
	fmt.Println()
	fmt.Printf("2) Node — fleet.webhooks updated in %s", cfgPath)
	if existed {
		fmt.Printf(" (backup at %s.bak)", cfgPath)
		fmt.Println(" — the daemon hot-reloads fleet config, deliveries begin within seconds.")
	} else {
		fmt.Println()
		fmt.Println("   The daemon had no config file at boot and is not watching one —")
		fmt.Println("   restart Secure Agent once so it picks the webhook up.")
	}
}

// fleetEnrollConfigPath is the node config enroll edits (env-overridable for
// tests and multi-node setups).
func fleetEnrollConfigPath() string {
	if p := os.Getenv("SECURE_AGENT_CONFIG"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "secure-agent", "config.yaml")
}

// normalizeCollectorURL accepts a bare host[:port] or a full URL and returns
// the hook endpoint URL.
func normalizeCollectorURL(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("collector URL is required")
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%q is not a valid collector URL", raw)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/hooks/secure-agent"
	}
	return u.String(), nil
}

// generateSecret returns 32 hex chars of CSPRNG — the webhook shared secret.
func generateSecret() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("cannot generate secret: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// mergeFleetWebhookYAML inserts (or updates, keyed on url) a webhook entry
// under fleet.webhooks, preserving the rest of the document — comments and
// unrelated keys included. Empty input yields a minimal valid config.
func mergeFleetWebhookYAML(existing []byte, hookURL, secret string) ([]byte, error) {
	var doc yaml.Node
	if len(bytes.TrimSpace(existing)) > 0 {
		if err := yaml.Unmarshal(existing, &doc); err != nil {
			return nil, fmt.Errorf("existing config is malformed YAML (%w) — fix or remove it and retry", err)
		}
	}
	root := docRootMapping(&doc)
	fleetMap := mappingValueOrCreate(root, "fleet", yaml.MappingNode)
	webhooksSeq := mappingValueOrCreate(fleetMap, "webhooks", yaml.SequenceNode)

	for _, item := range webhooksSeq.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		if v := mappingValue(item, "url"); v != nil && v.Value == hookURL {
			// Re-enrolling the same collector rotates the secret in place —
			// no duplicate entries.
			setMappingScalar(item, "secret", secret)
			return yaml.Marshal(&doc)
		}
	}
	entry := &yaml.Node{Kind: yaml.MappingNode}
	setMappingScalar(entry, "url", hookURL)
	setMappingScalar(entry, "secret", secret)
	webhooksSeq.Content = append(webhooksSeq.Content, entry)
	return yaml.Marshal(&doc)
}

func docRootMapping(doc *yaml.Node) *yaml.Node {
	if doc.Kind == 0 {
		doc.Kind = yaml.DocumentNode
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		doc.Content = []*yaml.Node{{Kind: yaml.MappingNode}}
	}
	return doc.Content[0]
}

func mappingValue(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func setMappingValue(m *yaml.Node, key string, v *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = v
			return
		}
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, v)
}

func setMappingScalar(m *yaml.Node, key, val string) {
	setMappingValue(m, key, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: val})
}

// mappingValueOrCreate returns m[key], creating it with the given kind when
// absent (or when a type conflict would corrupt the merge — a scalar
// "fleet:" is replaced, not nested into).
func mappingValueOrCreate(m *yaml.Node, key string, kind yaml.Kind) *yaml.Node {
	if v := mappingValue(m, key); v != nil {
		if v.Kind != kind {
			v.Kind, v.Tag, v.Value, v.Content = kind, "", "", nil
		}
		return v
	}
	v := &yaml.Node{Kind: kind}
	setMappingValue(m, key, v)
	return v
}
