package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cavi-ai/secure-agent/daemon/internal/safefile"
	"gopkg.in/yaml.v3"
)

// WriteResourceControl atomically replaces only the resource_control mapping
// in the user's overlay. The yaml.Node round trip retains unrelated keys and
// comments, while the 0600 write keeps the local policy private.
func WriteResourceControl(path string, policy ResourceControlConfig) error {
	if path == "" {
		return fmt.Errorf("resource policy config path is empty")
	}
	if err := ValidateResourceControl(policy); err != nil {
		return err
	}
	var doc yaml.Node
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read resource policy config: %w", err)
	}
	if len(bytes.TrimSpace(existing)) > 0 {
		if err := yaml.Unmarshal(existing, &doc); err != nil {
			return fmt.Errorf("existing config is malformed YAML: %w", err)
		}
	}
	root := resourceDocRoot(&doc)
	var value yaml.Node
	if err := value.Encode(policy); err != nil {
		return fmt.Errorf("encode resource policy: %w", err)
	}
	setResourceMappingValue(root, "resource_control", &value)
	data, err := yaml.Marshal(&doc)
	if err != nil {
		return fmt.Errorf("render resource policy config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create resource policy config directory: %w", err)
	}
	if err := safefile.WriteFileAtomic(path, data, 0o600); err != nil {
		return fmt.Errorf("write resource policy config: %w", err)
	}
	return nil
}

func resourceDocRoot(doc *yaml.Node) *yaml.Node {
	if doc.Kind == 0 {
		doc.Kind = yaml.DocumentNode
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		doc.Content = []*yaml.Node{{Kind: yaml.MappingNode}}
	}
	return doc.Content[0]
}

func setResourceMappingValue(m *yaml.Node, key string, value *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = value
			return
		}
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value)
}
