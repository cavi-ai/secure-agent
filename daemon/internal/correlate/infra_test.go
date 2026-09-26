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
		// Literals without a PTR, seen live as "unknown" egress.
		"162.159.134.234":                       "Cloudflare",
		"2606:50c0:8002::154":                   "GitHub",
		"2600:9000:27a1:8c00:17:b174:6d00:93a1": "AWS CloudFront",
		"185.199.108.133":                       "GitHub",
		"151.101.1.194":                         "Fastly",
		"2a04:4e42::485":                        "Fastly",
		"evil-1e100.net.attacker.com":           "",
		"registry.npmjs.org":                    "",
		"logs.example.com":                      "",
		"8.8.8.8":                               "",
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

func TestIdentify(t *testing.T) {
	orig := lookupAddr
	t.Cleanup(func() { lookupAddr = orig })
	ptrCache = sync.Map{}
	lookupAddr = func(_ context.Context, ip string) ([]string, error) { return nil, errors.New("no ptr") }

	// The exact IPv6 that read as unidentifiable: Google Cloud's 2600:1901::/32.
	if id := Identify("2600:1901:0:9e23::"); id.Org != "Google Cloud" || id.Kind != "ipv6" {
		t.Fatalf("gcp v6 = %+v", id)
	}
	if id := Identify("2607:6bc0::10"); id.Org != "Anthropic" {
		t.Fatalf("anthropic v6 = %+v", id)
	}
	if id := Identify("34.36.133.15"); id.Kind != "ipv4" {
		t.Fatalf("v4 kind = %+v", id)
	}
	if id := Identify("not-an-ip.example.com"); id.Kind != "hostname" || id.Name == "" {
		t.Fatalf("hostname = %+v", id)
	}
	// A provider registry identifies as an org even though it is not the
	// agent's own API carrier.
	if id := Identify("registry.npmjs.org"); id.Org != "npm registry" {
		t.Fatalf("npm = %+v", id)
	}
}

// An address the coverage headline files under an infra org is identified as
// that org too, so the Egress row and its identity never disagree.
func TestIdentifyNamesEveryInfraPrefix(t *testing.T) {
	orig := lookupAddr
	t.Cleanup(func() { lookupAddr = orig })
	ptrCache = sync.Map{}
	lookupAddr = func(context.Context, string) ([]string, error) { return nil, errors.New("no ptr") }
	for _, r := range infraCIDRs {
		host := r.prefix.Addr().Next().String()
		if got := InfraOrg(host); got != r.org {
			t.Errorf("InfraOrg(%s in %s) = %q, want %q", host, r.prefix, got, r.org)
		}
		if id := Identify(host); id.Org != r.org {
			t.Errorf("Identify(%s in %s).Org = %q, want %q", host, r.prefix, id.Org, r.org)
		}
	}
}

// Identify must be broader than InfraOrg: it may name a provider for an IP the
// coverage headline deliberately leaves unclassified (VM hostnames).
func TestIdentifyPTRBroadensBeyondInfraOrg(t *testing.T) {
	orig := lookupAddr
	t.Cleanup(func() { lookupAddr = orig })
	ptrCache = sync.Map{}
	lookupAddr = func(_ context.Context, ip string) ([]string, error) {
		return []string{"17.46.190.35.bc.googleusercontent.com."}, nil
	}
	if got := InfraOrg("35.190.46.17"); got != "" {
		t.Fatalf("InfraOrg must stay narrow, got %q", got)
	}
	id := Identify("35.190.46.17")
	if id.Org != "Google Cloud" || id.Name == "" {
		t.Fatalf("Identify should name the provider: %+v", id)
	}
}

// IdentifyCached answers from the CIDR/suffix tables and the PTR cache only:
// list stamping must never block on DNS.
func TestIdentifyCachedNeverResolves(t *testing.T) {
	orig := lookupAddr
	t.Cleanup(func() { lookupAddr = orig })
	ptrCache = sync.Map{}
	calls := 0
	lookupAddr = func(_ context.Context, ip string) ([]string, error) {
		calls++
		return []string{"host-9.example.org."}, nil
	}
	if id := IdentifyCached("2606:4700:20::681a:4a4"); id.Org != "Cloudflare" || id.Kind != "ipv6" || id.IP != "2606:4700:20::681a:4a4" || id.Name != "" {
		t.Fatalf("IdentifyCached(cloudflare v6) = %+v", id)
	}
	if id := IdentifyCached("203.0.113.9"); id.Org != "" || id.Name != "" || id.Kind != "ipv4" {
		t.Fatalf("IdentifyCached(uncached v4) = %+v", id)
	}
	if id := IdentifyCached("api.cloudflare.com"); id.Kind != "hostname" || id.Org != "Cloudflare" || id.Name != "api.cloudflare.com" {
		t.Fatalf("IdentifyCached(hostname) = %+v", id)
	}
	if calls != 0 {
		t.Fatalf("IdentifyCached made %d resolver calls, want 0", calls)
	}
	// A PTR that Identify already resolved is reused, still without a call.
	if id := Identify("203.0.113.9"); id.Name != "host-9.example.org" || calls != 1 {
		t.Fatalf("Identify = %+v after %d calls", id, calls)
	}
	if id := IdentifyCached("203.0.113.9"); id.Name != "host-9.example.org" || calls != 1 {
		t.Fatalf("IdentifyCached after Identify = %+v, calls %d", id, calls)
	}
}
