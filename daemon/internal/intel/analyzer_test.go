package intel

import (
	"encoding/json"
	"os"
	"path/filepath"
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
		Evidence: model.EvidenceFromStrings("file:/Users/test/.env", "net:1.2.3.4:443"),
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

// Paths that used to be mis-flagged as critical credentials must no longer be:
// a bare config/credentials basename is not AWS, "keychain" anywhere is not the
// Keychain DB, and a non-key file under ~/.ssh is not a private key.
func TestAnalyzer_ClassifyPaths_NoFalsePositives(t *testing.T) {
	analyzer := NewAnalyzer()
	for _, p := range []string{
		"/Users/user/.ssh/config",
		"/Users/user/.ssh/known_hosts",
		"/Users/user/.ssh/id_ed25519.pub",
		"/Users/user/project/.git/config",
		"/Users/user/src/keychain-demo/README.md",
		"/Users/user/app/config",
	} {
		if item := analyzer.classifyPath(p); item != nil {
			t.Errorf("classifyPath(%s) = %+v; want nil (no false-positive critical)", p, item)
		}
	}
}

// The incident analyzer and the flag classifier agree on environment files
// and SSH keys (daemon/internal/sensitive/testdata/paths.json): a template
// such as .env.example is not a Critical rotate item.
func TestAnalyzerFollowsTheSharedPathRules(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "sensitive", "testdata", "paths.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []struct {
			Path          string `json:"path"`
			SSHPrivateKey bool   `json:"ssh_private_key"`
			EnvSecret     bool   `json:"env_secret"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	analyzer := NewAnalyzer()
	for _, tc := range f.Cases {
		item := analyzer.classifyPath(tc.Path)
		switch {
		case tc.SSHPrivateKey:
			if item == nil || item.Category != model.CategorySSHKeys {
				t.Errorf("classifyPath(%s) = %+v, want an SSH key item", tc.Path, item)
			}
		case tc.EnvSecret:
			if item == nil || item.Category != model.CategoryEnvSecrets {
				t.Errorf("classifyPath(%s) = %+v, want an environment file item", tc.Path, item)
			}
		default:
			if item != nil {
				t.Errorf("classifyPath(%s) = %+v, want nothing to rotate", tc.Path, item)
			}
		}
	}
}

func TestSubjectForFlag(t *testing.T) {
	cases := []struct {
		name     string
		evidence []string
		want     string
	}{
		{"conn prefix", []string{"conn:evil.example.com:443"}, "evil.example.com:443"},
		{"file prefix", []string{"file:/Users/x/.aws/credentials"}, "/Users/x/.aws/credentials"},
		{"prose conn", []string{"codex (pid 1) read /x at t, then connected to evil.example.com:443 at t2"}, "evil.example.com:443"},
		{"prose file", []string{"codex (pid 1) read /Users/x/.env at t"}, "/Users/x/.env"},
		{"none", []string{"something happened"}, ""},
	}
	for _, c := range cases {
		if got := SubjectForFlag(model.Flag{Evidence: model.EvidenceFromStrings(c.evidence...)}); got != c.want {
			t.Errorf("%s: subject = %q, want %q", c.name, got, c.want)
		}
	}
}
