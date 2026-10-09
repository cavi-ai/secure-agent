package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
)

func TestFirewallModePersistenceFailureKeepsEnforcement(t *testing.T) {
	a := explainTestAPI(t)
	var err error
	a.fwEngine, err = firewall.NewEngine(config.FirewallConfig{Mode: "block"}, []byte("test-salt"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "modes.json")
	const corrupt = `{broken`
	if err := os.WriteFile(path, []byte(corrupt), 0o600); err != nil {
		t.Fatal(err)
	}
	a.fwModes = firewall.NewModeStore(path)
	before := a.fwEngine.RuleMode("aws-key")
	w := call(t, a, "POST", "/firewall/mode", `{"rule":"aws-key","mode":"monitor"}`)
	if w.Code != 500 {
		t.Errorf("status = %d: %s", w.Code, w.Body)
	}
	if got := a.fwEngine.RuleMode("aws-key"); got != before {
		t.Errorf("failed edit changed enforcement: %v -> %v", before, got)
	}
	if audit := a.store.RecentAudit(10); len(audit) != 0 {
		t.Errorf("failed edit wrote audit: %+v", audit)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != corrupt {
		t.Errorf("policy changed: %q, %v", got, err)
	}
}

func TestFirewallSourceLoadFailureHasNoSideEffects(t *testing.T) {
	for _, data := range []string{`{broken`, `null`} {
		for _, op := range []string{"add", "remove"} {
			t.Run(data+"/"+op, func(t *testing.T) {
				a := explainTestAPI(t)
				dir := t.TempDir()
				path, source := filepath.Join(dir, "sources.json"), filepath.Join(dir, "app.env")
				if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(source, []byte("# empty fixture\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				a.fwSources = firewall.NewSourceStore(path)
				ingestCalls := 0
				a.fwIngest = func() ([]string, error) { ingestCalls++; return nil, nil }
				body, err := json.Marshal(sourceRequest{Source: source, Op: op})
				if err != nil {
					t.Fatal(err)
				}
				w := call(t, a, "POST", "/firewall/sources", string(body))
				if w.Code != 500 {
					t.Errorf("status = %d: %s", w.Code, w.Body)
				}
				if ingestCalls != 0 {
					t.Errorf("failed edit re-ingested %d times", ingestCalls)
				}
				if audit := a.store.RecentAudit(10); len(audit) != 0 {
					t.Errorf("failed edit wrote audit: %+v", audit)
				}
				if got, err := os.ReadFile(path); err != nil || string(got) != data {
					t.Errorf("policy changed: %q, %v", got, err)
				}
			})
		}
	}
}
