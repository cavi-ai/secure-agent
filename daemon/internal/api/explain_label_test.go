package api

import "testing"

// The served allow-host label must never carry an IPv6 literal in the
// button text — the popover and the web console (web_dist/lib.js
// explainActionLabel) both read the same "this <Org> address" wording for
// an IPv6 host instead. Hostnames and IPv4 addresses are unaffected.
func TestAllowHostLabelDropsIPv6Literal(t *testing.T) {
	cases := []struct {
		subtest          string
		displayName      string
		host, org, agent string
		want             string
	}{
		{"ipv6 with org", "2606:4700:20::681a:4a4 (Cloudflare)", "2606:4700:20::681a:4a4", "Cloudflare", "claude",
			"Allow this Cloudflare address for claude"},
		{"ipv6 without org", "2606:4700:20::681a:4a4", "2606:4700:20::681a:4a4", "", "claude",
			"Allow this address for claude"},
		{"hostname unaffected", "api.example.com", "api.example.com", "", "cursor",
			"Allow api.example.com for cursor"},
		{"hostname with org unaffected", "api.example.com (AWS)", "api.example.com", "AWS", "cursor",
			"Allow api.example.com (AWS) for cursor"},
		{"ipv4 unaffected", "1.2.3.4", "1.2.3.4", "", "codex",
			"Allow 1.2.3.4 for codex"},
	}
	for _, c := range cases {
		t.Run(c.subtest, func(t *testing.T) {
			if got := allowHostLabel(c.displayName, c.host, c.org, c.agent); got != c.want {
				t.Fatalf("allowHostLabel(%q,%q,%q,%q) = %q, want %q", c.displayName, c.host, c.org, c.agent, got, c.want)
			}
		})
	}
}
