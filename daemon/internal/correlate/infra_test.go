package correlate

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestInfraOrg(t *testing.T) {
	cases := map[string]string{
		"2606:4700:4408::ac40:9bd1":                 "Cloudflare",
		"104.18.18.125":                             "Cloudflare",
		"2607:f8b0:400c:c28::54":                    "Google",
		"2001:4860:4828:7700::":                     "Google",
		"mia07s46-in-x0e.1e100.net":                 "Google",
		"ec2-98-90-104-193.compute-1.amazonaws.com": "AWS",
		"ec2-3-224-61-78.compute-1.amazonaws.com":   "AWS",
		"d111111abcdef8.cloudfront.net":             "AWS CloudFront",
		"lb-140-82-113-4-iad.github.com":            "GitHub",
		"140.82.113.4":                              "GitHub",
		"e13678.dscb.akamaiedge.net":                "Akamai",
		"evil-1e100.net.attacker.com":               "",
		"registry.npmjs.org":                        "",
		"logs.example.com":                          "",
		"8.8.8.8":                                   "",
	}
	for host, want := range cases {
		if got := InfraOrg(host); got != want {
			t.Errorf("InfraOrg(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestInfraOrgPTR(t *testing.T) {
	orig := lookupAddr
	t.Cleanup(func() { lookupAddr = orig })
	ptrCache = sync.Map{}
	lookupAddr = func(_ context.Context, ip string) ([]string, error) {
		switch ip {
		case "98.90.104.193":
			return []string{"ec2-98-90-104-193.compute-1.amazonaws.com."}, nil
		case "35.190.46.17":
			return []string{"17.46.190.35.bc.googleusercontent.com."}, nil
		case "203.0.113.9":
			return nil, errors.New("no such host")
		}
		return nil, nil
	}
	if got := InfraOrg("98.90.104.193"); got != "AWS" {
		t.Fatalf("PTR-classified EC2 = %q, want AWS", got)
	}
	if got := InfraOrg("203.0.113.9"); got != "" {
		t.Fatalf("unresolvable IP = %q, want unknown", got)
	}
	// googleusercontent.com is not in the suffix table — deliberate: VM
	// hostnames tell us nothing about which service the IP fronts.
	if got := InfraOrg("35.190.46.17"); got != "" {
		t.Fatalf("googleusercontent PTR = %q, want unknown (VM names are not service identity)", got)
	}
	// Cached: a repeat lookup must not hit the resolver.
	lookupAddr = func(context.Context, string) ([]string, error) {
		t.Fatal("resolver hit on cached entry")
		return nil, nil
	}
	if got := InfraOrg("98.90.104.193"); got != "AWS" {
		t.Fatalf("cached PTR = %q, want AWS", got)
	}
}
