package config

import (
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"
)

// ValidateFirewallPatterns rejects ambiguous IDs and invalid detectors before
// any persisted or running policy is changed. Go's regex engine is bounded.
func ValidateFirewallPatterns(patterns []PatternConfig) error {
	if len(patterns) > 256 {
		return fmt.Errorf("at most 256 patterns are allowed")
	}
	seen := map[string]bool{}
	for _, p := range patterns {
		if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`).MatchString(p.ID) || p.ID == "entropy" || seen[p.ID] {
			return fmt.Errorf("invalid or duplicate pattern ID")
		}
		seen[p.ID] = true
		if p.Mode != "monitor" && p.Mode != "block" {
			return fmt.Errorf("pattern %s: mode must be monitor or block", p.ID)
		}
		switch p.Type {
		case "", "unknown", "vendor-key", "cloud-key", "private-key", "env-value":
		default:
			return fmt.Errorf("pattern %s: unsupported secret type", p.ID)
		}
		if len(p.Re) == 0 || len(p.Re) > 4096 {
			return fmt.Errorf("pattern %s: expression must contain 1..4096 characters", p.ID)
		}
		re, err := regexp.Compile(p.Re)
		if err != nil {
			return fmt.Errorf("pattern %s: invalid regular expression", p.ID)
		}
		if re.MatchString("") {
			return fmt.Errorf("pattern %s: expression must not match empty text", p.ID)
		}
	}
	return nil
}

// WriteFirewallPatterns replaces only the pattern list; unrelated overlay keys
// and comments are preserved. Refuse aliases rather than modifying shared nodes.
func WriteFirewallPatterns(path string, patterns []PatternConfig) error {
	if path == "" {
		return fmt.Errorf("config path is empty")
	}
	if err := ValidateFirewallPatterns(patterns); err != nil {
		return err
	}
	doc, root, err := readOverlayDocument(path)
	if err != nil {
		return err
	}
	var fw *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "firewall" {
			fw = root.Content[i+1]
		}
	}
	if fw == nil {
		fw = &yaml.Node{Kind: yaml.MappingNode}
		setResourceMappingValue(root, "firewall", fw)
	}
	if fw.Kind != yaml.MappingNode || fw.Anchor != "" {
		return fmt.Errorf("firewall config must be an unaliased mapping")
	}
	var fields map[string]yaml.Node
	if err := fw.Decode(&fields); err != nil {
		return fmt.Errorf("invalid firewall mapping: %w", err)
	}
	for i := 0; i+1 < len(fw.Content); i += 2 {
		if fw.Content[i].Value == "<<" {
			return fmt.Errorf("firewall merge keys must be expanded before editing")
		}
	}
	if patterns == nil {
		patterns = []PatternConfig{}
	}
	var value yaml.Node
	if err := value.Encode(patterns); err != nil {
		return err
	}
	setResourceMappingValue(fw, "patterns", &value)
	return writeOverlayDocument(path, doc)
}
