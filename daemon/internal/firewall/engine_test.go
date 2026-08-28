package firewall

import (
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

func testEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine(config.FirewallConfig{
		Mode: "monitor",
		Patterns: []config.PatternConfig{
			{ID: "aws-key", Type: TypeCloudKey, Re: `AKIA[0-9A-Z]{16}`, Mode: "block"},
			{ID: "anthropic-key", Type: TypeVendorKey, Re: `sk-ant-[A-Za-z0-9_-]{24,}`, Mode: "monitor"},
		},
		Entropy: config.EntropyConfig{Enabled: false},
		Vendors: map[string]config.VendorConfig{
			"claude": {Hosts: []string{"api.anthropic.com"}, AuthHeader: "authorization"},
		},
		Context: config.ContextConfig{AllowOwnVendorAuth: true, TreatBodySecretAsLeak: true},
	}, []byte("salt"))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestInspectLegitVendorAuthAllows(t *testing.T) {
	e := testEngine(t)
	d := e.Inspect(Request{
		Agent: "claude", Host: "api.anthropic.com", AuthHeaderName: "authorization",
		Headers: map[string]string{"authorization": "Bearer sk-ant-abcdefghijklmnopqrstuvwxyz012345"},
	})
	if d.Action != ActionAllow {
		t.Fatalf("own vendor auth must allow, got %v (%+v)", d.Action, d.Findings)
	}
}

func TestInspectSecretToForeignHostBlocksInBlockMode(t *testing.T) {
	e := testEngine(t)
	d := e.Inspect(Request{
		Agent: "claude", Host: "logs.example.com", AuthHeaderName: "authorization",
		Body: []byte(`{"log":"key=AKIAIOSFODNN7EXAMPLE"}`),
	})
	if d.Action != ActionBlock {
		t.Fatalf("aws key (block mode) to foreign host must block, got %v (%+v)", d.Action, d.Findings)
	}
}

func TestInspectMonitorLeakWouldBlockNotBlock(t *testing.T) {
	e := testEngine(t)
	d := e.Inspect(Request{
		Agent: "claude", Host: "logs.example.com", AuthHeaderName: "authorization",
		Body: []byte("sk-ant-abcdefghijklmnopqrstuvwxyz012345"),
	})
	if d.Action != ActionWouldBlock {
		t.Fatalf("monitor-mode leak must be would-block, got %v (%+v)", d.Action, d.Findings)
	}
}
