package modelservice

import (
	"errors"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"go.yaml.in/yaml/v3"
)

func clientConfiguration(path string, raw []byte, change Change, key string) ([]byte, []string, error) {
	if change.Scope != "authenticated_inference" {
		return raw, []string{}, nil
	}
	cfg, err := config.LoadStrict(path)
	if err != nil {
		return nil, nil, errors.New("Secure Agent configuration is unavailable")
	}
	if cfg.SystemAgent.Enabled && sameEndpoint(cfg.SystemAgent.Endpoint, change.Port) {
		return nil, nil, errors.New("this endpoint is used by Ollama local chat; migrate that client before enabling bearer authentication")
	}
	fields := []string{}
	var doc yaml.Node
	if yaml.Unmarshal(raw, &doc) != nil || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil, errors.New("unsupported Secure Agent configuration document")
	}
	set := func(names ...string) error {
		node := doc.Content[0]
		for i, name := range names {
			if node.Kind != yaml.MappingNode {
				return errors.New("aliased model configuration requires manual review")
			}
			var child *yaml.Node
			for j := 0; j < len(node.Content); j += 2 {
				if node.Content[j].Value == name {
					child = node.Content[j+1]
					break
				}
			}
			if child == nil {
				child = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
				node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name}, child)
			}
			if i == len(names)-1 {
				*child = yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key, Style: yaml.DoubleQuotedStyle}
			} else {
				node = child
			}
		}
		return nil
	}
	for _, item := range []struct {
		match bool
		path  []string
		name  string
	}{
		{!cfg.Advisor.Managed && sameEndpoint(cfg.Advisor.Endpoint, change.Port), []string{"advisor", "api_key_file"}, "advisor.api_key_file"},
		{sameEndpoint(cfg.Advisor.ClassifierEndpoint, change.Port), []string{"advisor", "classifier_api_key_file"}, "advisor.classifier_api_key_file"},
		{sameEndpoint(cfg.DirectoryGuard.ShellReview.Endpoint, change.Port), []string{"directory_guard", "shell_review", "api_key_file"}, "directory_guard.shell_review.api_key_file"},
	} {
		if item.match {
			if err := set(item.path...); err != nil {
				return nil, nil, err
			}
			fields = append(fields, item.name)
		}
	}
	if len(fields) == 0 {
		return raw, fields, nil
	}
	updated, err := yaml.Marshal(&doc)
	return updated, fields, err
}
