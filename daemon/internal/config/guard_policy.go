package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/safefile"
)

func ValidateGuardPolicy(doc GuardRuleDoc) error {
	if doc.Rules == nil || doc.DirScan == nil || len(doc.Rules) > 256 {
		return fmt.Errorf("guard policy must contain rules and dir_scan arrays (at most 256 rules)")
	}
	seen := map[string]bool{}
	for _, rule := range doc.Rules {
		if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`).MatchString(rule.ID) || seen[rule.ID] {
			return fmt.Errorf("invalid or duplicate guard rule ID")
		}
		seen[rule.ID] = true
		if rule.Mode != "monitor" && rule.Mode != "prompt" && rule.Mode != "deny" {
			return fmt.Errorf("guard rule %s: invalid mode", rule.ID)
		}
		if len(rule.Paths) == 0 || len(rule.Paths) > 64 {
			return fmt.Errorf("guard rule %s needs 1..64 paths", rule.ID)
		}
		for _, p := range rule.Paths {
			if strings.TrimSpace(p) != p || p == "" || len(p) > 4096 || strings.ContainsAny(p, "\x00\r\n") {
				return fmt.Errorf("guard rule %s: invalid path", rule.ID)
			}
		}
	}
	for _, pair := range doc.DirScan {
		if len(pair) != 2 || pair[0] == "" || !seen[pair[1]] {
			return fmt.Errorf("invalid directory scan rule")
		}
	}
	return nil
}

// LoadGuardPolicy uses shipped rules only when the override is absent. A
// corrupt override must never be overwritten or treated as empty policy.
func LoadGuardPolicy(path string) (GuardRuleDoc, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		data = guardRulesBytes
	} else if err != nil {
		return GuardRuleDoc{}, err
	}
	var doc GuardRuleDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return doc, err
	}
	return doc, ValidateGuardPolicy(doc)
}

func WriteGuardPolicy(path string, doc GuardRuleDoc) error {
	if err := ValidateGuardPolicy(doc); err != nil {
		return err
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return safefile.WriteFileAtomic(path, data, 0600)
}
