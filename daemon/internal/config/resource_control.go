package config

import (
	"bytes"
	"fmt"
	"io"
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
	doc, root, err := readOverlayDocument(path)
	if err != nil {
		return err
	}
	var value yaml.Node
	if err := value.Encode(policy); err != nil {
		return fmt.Errorf("encode resource policy: %w", err)
	}
	setResourceMappingValue(root, "resource_control", &value)
	return writeOverlayDocument(path, doc)
}

func readOverlayDocument(path string) (*yaml.Node, *yaml.Node, error) {
	var doc yaml.Node
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("read config: %w", err)
	}
	if len(bytes.TrimSpace(existing)) > 0 {
		decoder := yaml.NewDecoder(bytes.NewReader(existing))
		if err := decoder.Decode(&doc); err != nil && err != io.EOF {
			return nil, nil, fmt.Errorf("existing config is malformed YAML: %w", err)
		}
		var extra yaml.Node
		if err := decoder.Decode(&extra); err != io.EOF {
			if err != nil {
				return nil, nil, fmt.Errorf("existing config has malformed trailing YAML: %w", err)
			}
			return nil, nil, fmt.Errorf("existing config must contain a single YAML document")
		}
	}
	root, err := resourceDocRoot(&doc)
	if err != nil {
		return nil, nil, err
	}
	return &doc, root, nil
}

func writeOverlayDocument(path string, doc *yaml.Node) error {
	data, err := yaml.Marshal(doc)
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

func resourceDocRoot(doc *yaml.Node) (*yaml.Node, error) {
	if doc.Kind == 0 {
		doc.Kind = yaml.DocumentNode
	}
	if len(doc.Content) == 0 {
		doc.Content = []*yaml.Node{{Kind: yaml.MappingNode}}
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("existing config must be a YAML mapping")
	}
	// Decoding only the root keys rejects duplicates without interpreting or
	// replacing unrelated values, including an old resource policy being fixed.
	var fields map[string]yaml.Node
	if err := doc.Content[0].Decode(&fields); err != nil {
		return nil, fmt.Errorf("existing config has invalid mapping keys: %w", err)
	}
	return doc.Content[0], nil
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
