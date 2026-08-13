package intel

import (
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestAnalyzer_Analyze(t *testing.T) {
	analyzer := NewAnalyzer()

	flag := model.Flag{
		ID:       "flag-1",
		Rule:     "sensitive-read-then-connect",
		Severity: 2,
		PID:      1234,
		Agent:    "cursor",
		TS:       time.Now(),
		Evidence: []string{"file:/Users/test/.env", "net:1.2.3.4:443"},
	}

	events := []event.Event{
		{
			PID:  1234,
			Path: "/Users/test/.aws/credentials",
		},
		{
			PID:        1234,
			RemoteHost: "5.6.7.8",
			RemotePort: 8080,
		},
	}

	report := analyzer.Analyze(flag, events)

	if report.FlagID != "flag-1" {
		t.Errorf("expected FlagID 'flag-1', got %s", report.FlagID)
	}

	if report.PID != 1234 {
		t.Errorf("expected PID 1234, got %d", report.PID)
	}

	if report.Risk != model.RiskCritical {
		t.Errorf("expected RiskCritical, got %s", report.Risk)
	}

	if len(report.RotateList) < 2 {
		t.Fatalf("expected at least 2 rotate items (.aws and .env), got %d", len(report.RotateList))
	}

	hasAWS := false
	hasEnv := false
	for _, item := range report.RotateList {
		if item.Category == model.CategoryCloudCreds {
			hasAWS = true
		}
		if item.Category == model.CategoryEnvSecrets {
			hasEnv = true
		}
	}

	if !hasAWS {
		t.Errorf("expected RotateList to contain CLOUD_CREDENTIALS")
	}
	if !hasEnv {
		t.Errorf("expected RotateList to contain ENV_SECRETS")
	}

	md := analyzer.GenerateMarkdown(report)
	if !strings.Contains(md, "# 🚨 Incident Containment & Rotation Report") {
		t.Errorf("expected markdown header, got: %s", md)
	}
	if !strings.Contains(md, "AWS Cloud Credentials") {
		t.Errorf("expected markdown to contain AWS Credentials item")
	}
}

func TestAnalyzer_ClassifyPaths(t *testing.T) {
	analyzer := NewAnalyzer()

	tests := []struct {
		path     string
		category model.SecretCategory
	}{
		{"/Users/user/.env", model.CategoryEnvSecrets},
		{"/Users/user/.env.production", model.CategoryEnvSecrets},
		{"/Users/user/.aws/credentials", model.CategoryCloudCreds},
		{"/Users/user/.ssh/id_ed25519", model.CategorySSHKeys},
		{"/Users/user/Library/Keychains/login.keychain-db", model.CategoryKeychain},
		{"/Users/user/.config/gh/hosts.yml", model.CategorySourceControl},
		{"/Users/user/.zshrc", model.CategorySystemConfig},
	}

	for _, tt := range tests {
		item := analyzer.classifyPath(tt.path)
		if item == nil {
			t.Fatalf("expected classifyPath(%s) to return non-nil item", tt.path)
		}
		if item.Category != tt.category {
			t.Errorf("classifyPath(%s) category = %s, expected %s", tt.path, item.Category, tt.category)
		}
	}
}
