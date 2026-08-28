package firewall

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

type fixtureReq struct {
	Agent      string            `json:"agent"`
	Host       string            `json:"host"`
	AuthHeader string            `json:"auth_header"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
}

func loadFixtures(t *testing.T, path string) []fixtureReq {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var reqs []fixtureReq
	if err := json.Unmarshal(data, &reqs); err != nil {
		t.Fatal(err)
	}
	return reqs
}

func corpusEngine(t *testing.T) *Engine {
	t.Helper()
	// Absent overlay path -> embedded defaults, independent of any real
	// ~/.config overlay on the developer's machine.
	cfg, err := config.Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// Force block mode so a leak yields ActionBlock and a false positive is visible.
	for i := range cfg.Firewall.Patterns {
		cfg.Firewall.Patterns[i].Mode = "block"
	}
	e, err := NewEngine(cfg.Firewall, []byte("corpus-salt"))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func toRequest(f fixtureReq) Request {
	return Request{Agent: f.Agent, Host: f.Host, AuthHeaderName: f.AuthHeader, Headers: f.Headers, Body: []byte(f.Body)}
}

// TestNoFalsePositivesOverLegitCorpus is the gate for enabling enforcement:
// legitimate agent traffic must never produce a blocking verdict.
func TestNoFalsePositivesOverLegitCorpus(t *testing.T) {
	e := corpusEngine(t)
	for i, f := range loadFixtures(t, "testdata/legit_requests.json") {
		if d := e.Inspect(toRequest(f)); d.Action == ActionBlock {
			t.Fatalf("false positive on legit fixture %d (%s -> %s): %+v", i, f.Agent, f.Host, d.Findings)
		}
	}
}

func TestLeakCorpusIsCaught(t *testing.T) {
	e := corpusEngine(t)
	for i, f := range loadFixtures(t, "testdata/leak_requests.json") {
		if d := e.Inspect(toRequest(f)); d.Action != ActionBlock {
			t.Fatalf("missed leak on fixture %d (%s -> %s): action=%v", i, f.Agent, f.Host, d.Action)
		}
	}
}
