package firewall

import (
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

func testPolicy(t *testing.T) *Policy {
	t.Helper()
	return NewPolicy(config.FirewallConfig{
		Mode: "monitor",
		Patterns: []config.PatternConfig{
			{ID: "anthropic-key", Type: TypeVendorKey, Mode: "block"},
			{ID: "aws-key", Type: TypeCloudKey, Mode: "monitor"},
		},
		Vendors: map[string]config.VendorConfig{
			"claude": {Hosts: []string{"api.anthropic.com"}, AuthHeader: "authorization"},
		},
		Context: config.ContextConfig{AllowOwnVendorAuth: true, TreatBodySecretAsLeak: true},
	})
}

func TestClassifyOwnVendorAuthIsLegit(t *testing.T) {
	p := testPolicy(t)
	v := p.Classify(
		Hit{RuleID: "anthropic-key", SecretType: TypeVendorKey, Layer: LayerPattern},
		RequestCtx{Agent: "claude", Host: "api.anthropic.com", Field: FieldAuthHeader},
	)
	if v.Kind != VerdictLegit || v.Action != ActionAllow {
		t.Fatalf("own-vendor auth must be legit/allow, got %+v", v)
	}
}

func TestClassifySecretInBodyIsLeak(t *testing.T) {
	p := testPolicy(t)
	v := p.Classify(
		Hit{RuleID: "anthropic-key", SecretType: TypeVendorKey, Layer: LayerPattern},
		RequestCtx{Agent: "claude", Host: "api.anthropic.com", Field: FieldBody},
	)
	if v.Kind != VerdictLeak {
		t.Fatalf("secret in body must be a leak, got %+v", v)
	}
	if v.Mode != ModeBlock || v.Action != ActionBlock {
		t.Fatalf("block-mode leak must yield ActionBlock, got %+v", v)
	}
}

func TestClassifyForeignHostIsLeak(t *testing.T) {
	p := testPolicy(t)
	v := p.Classify(
		Hit{RuleID: "aws-key", SecretType: TypeCloudKey, Layer: LayerPattern},
		RequestCtx{Agent: "claude", Host: "evil.example.com", Field: FieldAuthHeader},
	)
	if v.Kind != VerdictLeak {
		t.Fatalf("secret to a non-vendor host must be a leak, got %+v", v)
	}
	if v.Mode != ModeMonitor || v.Action != ActionWouldBlock {
		t.Fatalf("monitor-mode leak must be ActionWouldBlock, got %+v", v)
	}
}

func TestClassifyEntropyIsSuspectMonitorOnly(t *testing.T) {
	p := testPolicy(t)
	v := p.Classify(
		Hit{RuleID: "entropy", SecretType: TypeUnknown, Layer: LayerEntropy},
		RequestCtx{Agent: "claude", Host: "evil.example.com", Field: FieldBody},
	)
	if v.Kind != VerdictSuspect || v.Action != ActionAllow {
		t.Fatalf("entropy hits are suspect/allow, got %+v", v)
	}
}
