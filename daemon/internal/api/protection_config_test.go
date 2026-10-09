package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
)

func TestFirewallPatternCRUDPersistsAndApplies(t *testing.T) {
	a := explainTestAPI(t)
	a.configPath = filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(a.configPath, []byte("# keep me\nproxy_enabled: false\nfirewall:\n  mode: block\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(a.configPath)
	if err != nil {
		t.Fatal(err)
	}
	a.fwEngine, err = firewall.NewEngine(cfg.Firewall, []byte("fixture-salt"))
	if err != nil {
		t.Fatal(err)
	}
	post := func(body string, status int) {
		t.Helper()
		w := call(t, a, "POST", "/firewall/patterns", body)
		if w.Code != status {
			t.Fatalf("status %d: %s", w.Code, w.Body)
		}
	}
	post(`{"op":"add","pattern":{"id":"fixture","type":"vendor-key","re":"fixture_[A-Z]{8}","mode":"block"}}`, 200)
	if d := a.fwEngine.Inspect(firewall.Request{Host: "foreign.test", Body: []byte("fixture_ABCDEFGH")}); d.Action != firewall.ActionBlock {
		t.Fatalf("new pattern not enforced: %+v", d)
	}
	post(`{"op":"edit","id":"fixture","pattern":{"id":"fixture","type":"vendor-key","re":"updated_[A-Z]{8}","mode":"block"}}`, 200)
	if hits := a.fwEngine.ScanText("fixture_ABCDEFGH"); len(hits) != 0 {
		t.Fatalf("old pattern still matches: %+v", hits)
	}
	cfg, err = config.Load(a.configPath)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := firewall.NewEngine(cfg.Firewall, []byte("fixture-salt"))
	if err != nil {
		t.Fatal(err)
	}
	if d := restarted.Inspect(firewall.Request{Host: "foreign.test", Body: []byte("updated_ABCDEFGH")}); d.Action != firewall.ActionBlock {
		t.Fatalf("edit not durable: %+v", d)
	}
	data, _ := os.ReadFile(a.configPath)
	if !strings.Contains(string(data), "# keep me") || !strings.Contains(string(data), "proxy_enabled: false") {
		t.Fatal("unrelated config lost")
	}
	post(`{"op":"remove","id":"fixture"}`, 200)
	if hits := a.fwEngine.ScanText("updated_ABCDEFGH"); len(hits) != 0 {
		t.Fatalf("removed pattern still matches: %+v", hits)
	}
	if _, ok := a.fwEngine.Stats()["fixture"]; ok {
		t.Fatal("removed rule still listed")
	}
	cfg, err = config.Load(a.configPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range cfg.Firewall.Patterns {
		if p.ID == "fixture" {
			t.Fatal("remove not persisted")
		}
	}
}

func TestFirewallPatternFailedSaveKeepsProtection(t *testing.T) {
	for _, bad := range []string{"broken: [", "null", "firewall: null\n", "firewall: &fw {mode: block}\nother: *fw\n"} {
		t.Run(bad, func(t *testing.T) {
			a := explainTestAPI(t)
			a.configPath = filepath.Join(t.TempDir(), "config.yaml")
			os.WriteFile(a.configPath, []byte(bad), 0600)
			var err error
			a.fwEngine, err = firewall.NewEngine(config.FirewallConfig{Mode: "block", Patterns: []config.PatternConfig{{ID: "fixture", Re: "fixture_[A-Z]{8}", Mode: "block"}}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			w := call(t, a, "POST", "/firewall/patterns", `{"op":"remove","id":"fixture"}`)
			if w.Code != 500 {
				t.Fatalf("status %d: %s", w.Code, w.Body)
			}
			if len(a.fwEngine.ScanText("fixture_ABCDEFGH")) != 1 {
				t.Fatal("failed save changed detector")
			}
			data, _ := os.ReadFile(a.configPath)
			if string(data) != bad {
				t.Fatal("failed save modified config")
			}
		})
	}
}

func TestProtectionConfigRejectsInvalidEdits(t *testing.T) {
	a := explainTestAPI(t)
	a.configPath = filepath.Join(t.TempDir(), "config.yaml")
	a.socketPath = filepath.Join(t.TempDir(), "daemon.sock")
	cfg, _ := config.Load("")
	a.fwEngine, _ = firewall.NewEngine(cfg.Firewall, nil)
	for _, body := range []string{`{"op":"add","pattern":{"id":"bad","re":"[","mode":"monitor"}}`, `{"op":"add","pattern":{"id":"entropy","re":"x","mode":"monitor"}}`, `{"op":"remove","id":"absent"}`, `{"op":"add","pattern":{"id":"aws-key","re":"x","mode":"monitor"}}`} {
		w := call(t, a, "POST", "/firewall/patterns", body)
		if w.Code < 400 || w.Code >= 500 {
			t.Fatalf("invalid edit accepted: %d %s", w.Code, w.Body)
		}
	}
	w := call(t, a, "GET", "/guard/config", "")
	if w.Code != 200 {
		t.Fatalf("guard config %d: %s", w.Code, w.Body)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	w = call(t, a, "POST", "/guard/config", `{"op":"add","rule":{"id":"custom","paths":["~/private/**"],"mode":"deny","read_sensitive":true}}`)
	if w.Code != 200 {
		t.Fatalf("guard add %d: %s", w.Code, w.Body)
	}
	var guardDoc config.GuardRuleDoc
	if err := json.Unmarshal(w.Body.Bytes(), &guardDoc); err != nil {
		t.Fatal(err)
	}
	if guardDoc.Rules[0].ID != "custom" {
		t.Fatal("custom protection would be shadowed by shipped globs")
	}
	w = call(t, a, "POST", "/guard/config", `{"op":"edit","id":"custom","rule":{"id":"custom","paths":["~/private/keys/**"],"mode":"prompt","read_sensitive":true}}`)
	if w.Code != 200 {
		t.Fatalf("guard edit %d: %s", w.Code, w.Body)
	}
	persisted, err := os.ReadFile(filepath.Join(filepath.Dir(a.socketPath), "guard-rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(persisted), "~/private/keys/**") {
		t.Fatal("guard edit not durable")
	}
	w = call(t, a, "POST", "/guard/config", `{"op":"remove","id":"custom"}`)
	if w.Code != 200 {
		t.Fatalf("guard remove %d: %s", w.Code, w.Body)
	}
	w = call(t, a, "GET", "/guard/config", "")
	if strings.Contains(w.Body.String(), `"custom"`) {
		t.Fatal("removed rule listed")
	}
}

func TestGuardConfigCorruptionCannotBeOverwritten(t *testing.T) {
	for _, bad := range []string{`null`, `{broken`, `{"rules":null,"dir_scan":[]}`} {
		t.Run(bad, func(t *testing.T) {
			a := explainTestAPI(t)
			a.socketPath = filepath.Join(t.TempDir(), "daemon.sock")
			path := filepath.Join(filepath.Dir(a.socketPath), "guard-rules.json")
			if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
				t.Fatal(err)
			}
			w := call(t, a, "POST", "/guard/config", `{"op":"remove","id":"env-files"}`)
			if w.Code != 500 {
				t.Fatalf("status %d: %s", w.Code, w.Body)
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != bad {
				t.Fatalf("corrupt policy overwritten: %q %v", got, err)
			}
		})
	}
}
