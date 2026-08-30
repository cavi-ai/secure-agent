package firewall

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

// TestDefaultPatternsCatchCommonSecrets exercises the shipped pattern library
// against representative real-shaped secrets, so expanding the library is proven
// to add coverage (not just avoid false positives).
func TestDefaultPatternsCatchCommonSecrets(t *testing.T) {
	cfg, err := config.Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDetector(cfg.Firewall.Patterns, config.EntropyConfig{})
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"anthropic-key":      "sk-ant-abcdefghijklmnopqrstuvwxyz012345",
		"github-pat":         "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		"aws-key":            "AKIAIOSFODNN7EXAMPLE",
		"gitlab-pat":         "glpat-ABCDEFGHIJ1234567890",
		"npm-token":          "npm_abcdefghijklmnopqrstuvwxyz0123456789",
		"sendgrid-key":       "SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
		"stripe-webhook":     "whsec_" + strings.Repeat("a", 32),
		"digitalocean-token": "dop_v1_" + strings.Repeat("a", 64),
		"db-conn-string":     "postgres://user:s3cr3tpass@db.example.com:5432/app",
	}

	for wantRule, sample := range cases {
		found := false
		for _, h := range d.Scan(sample) {
			if h.RuleID == wantRule {
				found = true
			}
		}
		if !found {
			t.Errorf("rule %q did not match %q", wantRule, sample)
		}
	}
}

func testDetector(t *testing.T) *Detector {
	t.Helper()
	d, err := NewDetector([]config.PatternConfig{
		{ID: "aws-key", Type: TypeCloudKey, Re: `AKIA[0-9A-Z]{16}`, Mode: "monitor"},
		{ID: "anthropic-key", Type: TypeVendorKey, Re: `sk-ant-[A-Za-z0-9_-]{24,}`, Mode: "monitor"},
	}, config.EntropyConfig{Enabled: true, MinLen: 20, MinBits: 4.0, Mode: "monitor"})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestScanMatchesTypedPattern(t *testing.T) {
	d := testDetector(t)
	hits := d.Scan("token=AKIAIOSFODNN7EXAMPLE trailing")
	if len(hits) == 0 {
		t.Fatal("expected an AWS key hit")
	}
	if hits[0].RuleID != "aws-key" || hits[0].SecretType != TypeCloudKey || hits[0].Layer != LayerPattern {
		t.Fatalf("unexpected hit: %+v", hits[0])
	}
}

func TestScanNoFalsePositiveOnProse(t *testing.T) {
	d := testDetector(t)
	if hits := d.Scan("the quick brown fox writes some ordinary words"); len(hits) != 0 {
		t.Fatalf("prose should not match, got %+v", hits)
	}
}

func TestScanEntropyFlagsLongRandomToken(t *testing.T) {
	d := testDetector(t)
	hits := d.Scan("value=Zx9Kq2Lm8Pv4Rt6Wy1Bn3Df5Gh7Jk secret")
	found := false
	for _, h := range hits {
		if h.Layer == LayerEntropy {
			found = true
		}
	}
	if !found {
		t.Fatal("expected an entropy hit on a long high-entropy token")
	}
}
