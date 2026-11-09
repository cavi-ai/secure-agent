package modelservice

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"go.yaml.in/yaml/v3"
)

func clientConfiguration(path string, raw []byte, change Change, key string) ([]byte, []string, error) {
	if change.Scope != "authenticated_inference" && change.Scope != "browser_hardening" {
		return raw, []string{}, nil
	}
	cfg, err := config.LoadStrict(path)
	if err != nil {
		return nil, nil, errors.New("Secure Agent configuration is unavailable")
	}
	if change.Scope == "authenticated_inference" && cfg.SystemAgent.Enabled && sameEndpoint(cfg.SystemAgent.Endpoint, change.Port) {
		return nil, nil, errors.New("this endpoint is used by Ollama local chat; migrate that client before enabling bearer authentication")
	}
	fields := []string{}
	var doc yaml.Node
	if yaml.Unmarshal(raw, &doc) != nil || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil, errors.New("unsupported Secure Agent configuration document")
	}
	set := func(value string, names ...string) error {
		node := doc.Content[0]
		for i, name := range names {
			if node.Kind != yaml.MappingNode || node.Anchor != "" {
				return errors.New("aliased or anchored model configuration requires manual review")
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
				if child.Kind == yaml.AliasNode || child.Anchor != "" {
					return errors.New("aliased or anchored model configuration requires manual review")
				}
				*child = yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value, Style: yaml.DoubleQuotedStyle}
			} else {
				node = child
			}
		}
		return nil
	}
	for _, item := range []struct {
		match        bool
		endpoint     string
		endpointPath []string
		keyPath      []string
	}{
		{!cfg.Advisor.Managed && sameEndpoint(cfg.Advisor.Endpoint, change.Port), cfg.Advisor.Endpoint, []string{"advisor", "endpoint"}, []string{"advisor", "api_key_file"}},
		{sameEndpoint(cfg.Advisor.ClassifierEndpoint, change.Port), cfg.Advisor.ClassifierEndpoint, []string{"advisor", "classifier_endpoint"}, []string{"advisor", "classifier_api_key_file"}},
		{sameEndpoint(cfg.DirectoryGuard.ShellReview.Endpoint, change.Port), cfg.DirectoryGuard.ShellReview.Endpoint, []string{"directory_guard", "shell_review", "endpoint"}, []string{"directory_guard", "shell_review", "api_key_file"}},
		{change.Scope == "browser_hardening" && sameEndpoint(cfg.SystemAgent.Endpoint, change.Port), cfg.SystemAgent.Endpoint, []string{"system_agent", "endpoint"}, nil},
	} {
		if item.match {
			u, _ := url.Parse(item.endpoint)
			if u.Scheme != "http" {
				return nil, nil, errors.New("TLS client migration requires manual review; this adapter verifies local HTTP")
			}
			u.Host = net.JoinHostPort("127.0.0.1", strconv.Itoa(change.Port))
			if u.String() != item.endpoint {
				if err := set(u.String(), item.endpointPath...); err != nil {
					return nil, nil, err
				}
				fields = append(fields, strings.Join(item.endpointPath, "."))
			}
			if change.Scope == "authenticated_inference" {
				if err := set(key, item.keyPath...); err != nil {
					return nil, nil, err
				}
				fields = append(fields, strings.Join(item.keyPath, "."))
			}
		}
	}
	if len(fields) == 0 {
		return raw, fields, nil
	}
	updated, err := yaml.Marshal(&doc)
	return updated, fields, err
}
