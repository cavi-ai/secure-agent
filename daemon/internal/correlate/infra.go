package correlate

// InfraOrg classifies a destination as known CDN/cloud infrastructure —
// the carriers that front the agents' OWN API backends (Cloudflare, Google,
// AWS, GitHub, Akamai, Fastly, Azure). Unrouted traffic to these is a
// routing-coverage fact, not a per-endpoint finding: it must not inflate the
// uninspected-egress headline or spawn 100+ one-by-one Allow rows. Returns
// the org name, or "" for genuinely unknown endpoints (those stay
// actionable).

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// ptrTimeout bounds one reverse-DNS lookup. Classification runs on API
// handlers, never the drain loop, but a slow resolver must still not stall
// a read.
const ptrTimeout = 400 * time.Millisecond

// ptrMissTTL suppresses repeat lookups for IPs with no useful PTR (most of
// them), so a busy agent can't turn classification into a DNS hammer.
const ptrMissTTL = time.Hour

type ptrEntry struct {
	org string
	at  time.Time
}

var ptrCache sync.Map // ip -> ptrEntry

// lookupAddr is injectable for tests (no real DNS in unit tests).
var lookupAddr = func(ctx context.Context, ip string) ([]string, error) {
	return net.DefaultResolver.LookupAddr(ctx, ip)
}

// ptrOrg reverse-resolves a bare IP and classifies the PTR name. Results and
// misses are cached — classification happens per summary/count call.
func ptrOrg(ip string) string {
	if v, ok := ptrCache.Load(ip); ok {
		e := v.(ptrEntry)
		if e.org != "" || time.Since(e.at) < ptrMissTTL {
			return e.org
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), ptrTimeout)
	names, err := lookupAddr(ctx, ip)
	cancel()
	org := ""
	if err == nil {
		for _, n := range names {
			if o := infraBySuffix(strings.ToLower(strings.TrimSuffix(n, "."))); o != "" {
				org = o
				break
			}
		}
	}
	ptrCache.Store(ip, ptrEntry{org: org, at: time.Now()})
	return org
}

// infraCIDRs: bare-IP classification. Suffix rules below handle hostnames;
// agents often connect to literal IPs (IPv6 especially) where no name exists.
var infraCIDRs = []struct {
	org    string
	prefix netip.Prefix
}{
	{"Cloudflare", netip.MustParsePrefix("104.16.0.0/13")},
	{"Cloudflare", netip.MustParsePrefix("2606:4700::/32")},
	{"Google", netip.MustParsePrefix("2001:4860::/32")},
	{"Google", netip.MustParsePrefix("2607:f8b0::/32")},
	{"GitHub", netip.MustParsePrefix("140.82.112.0/20")},
}

// infraSuffixes: PTR-style hostname suffixes → org. Matched on the dot
// boundary so evil-1e100.net.attacker.com cannot spoof membership.
var infraSuffixes = []struct {
	suffix string
	org    string
}{
	{".1e100.net", "Google"},
	{".compute-1.amazonaws.com", "AWS"},
	{".amazonaws.com", "AWS"},
	{".cloudfront.net", "AWS CloudFront"},
	{".akamai.net", "Akamai"},
	{".akamaiedge.net", "Akamai"},
	{".akamaitechnologies.com", "Akamai"},
	{".fastly.net", "Fastly"},
	{".github.com", "GitHub"},
	{".azure.com", "Azure"},
	{".trafficmanager.net", "Azure"},
	{".cloudapp.net", "Azure"},
	{".cloudflare.com", "Cloudflare"},
}

// infraBySuffix matches PTR-style hostname suffixes → org, on the dot
// boundary so evil-1e100.net.attacker.com cannot spoof membership.
func infraBySuffix(h string) string {
	for _, s := range infraSuffixes {
		if strings.HasSuffix(h, s.suffix) {
			return s.org
		}
	}
	return ""
}

// InfraOrg returns the infrastructure org for host, or "" when the endpoint
// is not recognizable CDN/cloud infrastructure. Bare IPs without a CIDR rule
// fall back to a cached reverse-DNS lookup (EC2 and friends appear as
// literals more often than as names).
func InfraOrg(host string) string {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if ip, err := netip.ParseAddr(h); err == nil {
		for _, r := range infraCIDRs {
			if r.prefix.Contains(ip) {
				return r.org
			}
		}
		return ptrOrg(h)
	}
	return infraBySuffix(h)
}
