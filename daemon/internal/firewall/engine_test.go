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

func TestSetFingerprintsActivatesRegistry(t *testing.T) {
	e := testEngine(t) // built with salt []byte("salt"), no fingerprints
	secret := "s3cr3t-value-abcdefghijklmnop"
	req := Request{Agent: "claude", Host: "logs.example.com", AuthHeaderName: "authorization",
		Body: []byte("dump: " + secret)}

	for _, f := range e.Inspect(req).Findings {
		if f.Hit.Layer == LayerFingerprint {
			t.Fatal("no fingerprint should match before registration")
		}
	}

	e.SetFingerprints([]config.Fingerprint{
		{ID: "fp1", Type: TypeEnvValue, Len: len(secret), HMAC: Fingerprint([]byte("salt"), secret)},
	})

	found := false
	for _, f := range e.Inspect(req).Findings {
		if f.Hit.Layer == LayerFingerprint && f.Hit.RuleID == "fp1" && f.Verdict.Kind == VerdictLeak {
			found = true
		}
	}
	if !found {
		t.Fatal("registered fingerprint should be detected as a leak after SetFingerprints")
	}
}

func TestSetRuleModePromotesToBlock(t *testing.T) {
	e := testEngine(t) // anthropic-key starts in monitor mode
	leak := Request{Agent: "claude", Host: "logs.example.com", AuthHeaderName: "authorization",
		Body: []byte("sk-ant-abcdefghijklmnopqrstuvwxyz012345")}

	if d := e.Inspect(leak); d.Action != ActionWouldBlock {
		t.Fatalf("pre-promote: want would-block, got %v", d.Action)
	}

	e.SetRuleMode("anthropic-key", ModeBlock)
	if e.RuleMode("anthropic-key") != ModeBlock {
		t.Fatal("RuleMode should reflect the promotion")
	}
	if d := e.Inspect(leak); d.Action != ActionBlock {
		t.Fatalf("post-promote: want block, got %v", d.Action)
	}
}

func TestEngineStatsTally(t *testing.T) {
	e := testEngine(t) // aws-key: block mode, anthropic-key: monitor mode

	// block-mode leak (aws key in body to foreign host)
	e.Inspect(Request{Agent: "claude", Host: "logs.example.com", AuthHeaderName: "authorization",
		Body: []byte("AKIAIOSFODNN7EXAMPLE")})
	// monitor-mode leak (anthropic key in body)
	e.Inspect(Request{Agent: "claude", Host: "logs.example.com", AuthHeaderName: "authorization",
		Body: []byte("sk-ant-abcdefghijklmnopqrstuvwxyz012345")})
	// legit (anthropic key in auth header to its vendor host)
	e.Inspect(Request{Agent: "claude", Host: "api.anthropic.com", AuthHeaderName: "authorization",
		Headers: map[string]string{"authorization": "Bearer sk-ant-abcdefghijklmnopqrstuvwxyz012345"}})

	st := e.Stats()
	if st["aws-key"].Blocked != 1 {
		t.Fatalf("aws-key blocked = %d, want 1 (%+v)", st["aws-key"].Blocked, st)
	}
	if st["anthropic-key"].WouldBlock != 1 {
		t.Fatalf("anthropic-key would_block = %d, want 1 (%+v)", st["anthropic-key"].WouldBlock, st)
	}
	if st["anthropic-key"].Legit != 1 {
		t.Fatalf("anthropic-key legit = %d, want 1 (%+v)", st["anthropic-key"].Legit, st)
	}
	if st["aws-key"].Mode != "block" {
		t.Fatalf("aws-key mode = %q, want block", st["aws-key"].Mode)
	}
	if st["anthropic-key"].Mode != "monitor" {
		t.Fatalf("anthropic-key mode = %q, want monitor", st["anthropic-key"].Mode)
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

func TestRuleIDsOfTypeListsConfiguredPatterns(t *testing.T) {
	e := testEngine(t)
	got := e.RuleIDsOfType(TypeVendorKey)
	if len(got) != 1 || got[0] != "anthropic-key" {
		t.Fatalf("vendor-key ids = %v, want [anthropic-key]", got)
	}
	got = e.RuleIDsOfType(TypeCloudKey)
	if len(got) != 1 || got[0] != "aws-key" {
		t.Fatalf("cloud-key ids = %v, want [aws-key]", got)
	}
}

func TestStatsIncludesIdlePatternsWithType(t *testing.T) {
	e := testEngine(t)
	st := e.Stats()
	if st["anthropic-key"].Type != TypeVendorKey {
		t.Fatalf("anthropic-key type = %q, want %s", st["anthropic-key"].Type, TypeVendorKey)
	}
	if st["aws-key"].Type != TypeCloudKey {
		t.Fatalf("aws-key type = %q, want %s", st["aws-key"].Type, TypeCloudKey)
	}
	if st["anthropic-key"].Mode != "monitor" {
		t.Fatalf("idle anthropic-key mode = %q, want monitor", st["anthropic-key"].Mode)
	}
}

// ScanText finds a registered secret through its base64 encoding inside a JSON
// transcript line (fingerprint layer) and a typed key (pattern layer), and
// leaves the per-rule tallies untouched: it is not a proxied request.
func TestScanTextFindsFingerprintAndPatternHits(t *testing.T) {
	e := testEngine(t)
	secret := "s3cr3t-value-abcdefghijklmnop"
	e.SetFingerprints([]config.Fingerprint{
		{ID: "fp1", Type: TypeEnvValue, Len: len(secret), HMAC: Fingerprint([]byte("salt"), secret)},
	})

	line := `{"type":"tool_result","content":"env dump ` + base64Std(secret) + ` done"}`
	var fp *Hit
	for _, h := range e.ScanText(line) {
		if h.RuleID == "fp1" {
			fp = &h
		}
	}
	if fp == nil || fp.Layer != LayerFingerprint {
		t.Fatalf("base64-encoded registered secret: want fingerprint hit fp1, got %+v", fp)
	}

	var pat *Hit
	for _, h := range e.ScanText(`{"type":"assistant","text":"key=AKIAIOSFODNN7EXAMPLE"}`) {
		if h.RuleID == "aws-key" {
			pat = &h
		}
	}
	if pat == nil || pat.Layer != LayerPattern {
		t.Fatalf("typed key: want pattern hit aws-key, got %+v", pat)
	}

	if s := e.Stats()["aws-key"]; s.WouldBlock+s.Blocked+s.Legit+s.Suspect != 0 {
		t.Fatalf("ScanText must not tally, got %+v", s)
	}
	if got := e.ScanText(""); got != nil {
		t.Fatalf("empty text: want no hits, got %+v", got)
	}
}

// ScanText never runs the entropy layer: text that only trips entropy in
// Scan yields nothing, while a typed pattern still hits in both.
func TestScanTextSkipsEntropyLayer(t *testing.T) {
	e, err := NewEngine(config.FirewallConfig{
		Mode: "monitor",
		Patterns: []config.PatternConfig{
			{ID: "aws-key", Type: TypeCloudKey, Re: `AKIA[0-9A-Z]{16}`, Mode: "monitor"},
		},
		Entropy: config.EntropyConfig{Enabled: true, MinLen: 20, MinBits: 4.0, Mode: "monitor"},
	}, []byte("salt"))
	if err != nil {
		t.Fatal(err)
	}

	random := "value=Zx9Kq2Lm8Pv4Rt6Wy1Bn3Df5Gh7Jk secret"
	if hits := e.det.Scan(random); len(hits) != 1 || hits[0].Layer != LayerEntropy {
		t.Fatalf("Scan: want exactly one entropy hit, got %+v", hits)
	}
	if hits := e.ScanText(random); len(hits) != 0 {
		t.Fatalf("ScanText: want no hits on entropy-only text, got %+v", hits)
	}

	typed := "key=AKIAIOSFODNN7EXAMPLE"
	for name, hits := range map[string][]Hit{"Scan": e.det.Scan(typed), "ScanText": e.ScanText(typed)} {
		found := false
		for _, h := range hits {
			if h.RuleID == "aws-key" && h.Layer == LayerPattern {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s: want aws-key pattern hit, got %+v", name, hits)
		}
	}
}
