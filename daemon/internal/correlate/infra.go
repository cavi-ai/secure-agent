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
	org  string
	name string
	at   time.Time
}

var ptrCache sync.Map // ip -> ptrEntry

// lookupAddr is injectable for tests (no real DNS in unit tests).
var lookupAddr = func(ctx context.Context, ip string) ([]string, error) {
	return net.DefaultResolver.LookupAddr(ctx, ip)
}

// ptrOrg reverse-resolves a bare IP and classifies the PTR name. Results and
// misses are cached — classification happens per summary/count call.
func ptrOrg(ip string) string {
	return ptrOrgName(ip).Org
}

// ptrResult carries both the classification and the resolved PTR name, so the
// UI can show a human a name to reason about ("that's Google") rather than a
// bare address, even for infrastructure whose org we don't have a rule for.
type ptrResult struct {
	Org  string
	Name string // the first PTR name, without the trailing dot
}

func ptrOrgName(ip string) ptrResult {
	if v, ok := ptrCache.Load(ip); ok {
		e := v.(ptrEntry)
		if e.org != "" || time.Since(e.at) < ptrMissTTL {
			return ptrResult{Org: e.org, Name: e.name}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), ptrTimeout)
	names, err := lookupAddr(ctx, ip)
	cancel()
	res := ptrResult{}
	if err == nil {
		for _, n := range names {
			name := strings.TrimSuffix(n, ".")
			if res.Name == "" {
				res.Name = name
			}
			if o := infraBySuffix(strings.ToLower(name)); o != "" {
				res.Org = o
				break
			}
		}
	}
	ptrCache.Store(ip, ptrEntry{org: res.Org, name: res.Name, at: time.Now()})
	return res
}

// infraCIDRs: bare-IP classification for the COVERAGE HEADLINE only. Suffix
// rules below handle hostnames; agents often connect to literal IPs (IPv6
// especially) where no name exists. Kept deliberately narrow: these are the
// carriers that front the agents' OWN API backends, so classifying a random
// VM IP here would collapse legitimate per-endpoint findings. The broader
// "who owns this?" table used by the endpoint detail surface is providerCIDRs.
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

// providerCIDRs is the broader "who owns this?" table used only by Identify
// (the endpoint detail surface). Identifying an endpoint as Google Cloud / AWS
// / Azure is what stops an operator from blocking an agent's rightful traffic;
// it does NOT change the coverage-headline classification above.
var providerCIDRs = []struct {
	org    string
	prefix netip.Prefix
}{
	// Cloudflare.
	{"Cloudflare", netip.MustParsePrefix("104.16.0.0/13")},
	{"Cloudflare", netip.MustParsePrefix("172.64.0.0/13")},
	{"Cloudflare", netip.MustParsePrefix("2606:4700::/32")},
	// Google (search/API) + Google Cloud (GCP).
	{"Google", netip.MustParsePrefix("142.250.0.0/15")},
	{"Google", netip.MustParsePrefix("172.217.0.0/16")},
	{"Google", netip.MustParsePrefix("2001:4860::/32")},
	{"Google", netip.MustParsePrefix("2607:f8b0::/32")},
	{"Google Cloud", netip.MustParsePrefix("34.64.0.0/10")},
	{"Google Cloud", netip.MustParsePrefix("35.184.0.0/13")},
	{"Google Cloud", netip.MustParsePrefix("35.192.0.0/12")},
	{"Google Cloud", netip.MustParsePrefix("2600:1900::/28")},
	{"Google Cloud", netip.MustParsePrefix("2600:1901::/32")},
	// AWS.
	{"AWS", netip.MustParsePrefix("3.0.0.0/9")},
	{"AWS", netip.MustParsePrefix("18.0.0.0/8")},
	{"AWS", netip.MustParsePrefix("52.0.0.0/8")},
	{"AWS", netip.MustParsePrefix("54.0.0.0/8")},
	{"AWS", netip.MustParsePrefix("2600:1f00::/24")},
	{"AWS", netip.MustParsePrefix("2a05:d000::/24")},
	// GitHub.
	{"GitHub", netip.MustParsePrefix("140.82.112.0/20")},
	{"GitHub", netip.MustParsePrefix("192.30.252.0/22")},
	// Anthropic (Claude API frontends).
	{"Anthropic", netip.MustParsePrefix("160.79.104.0/23")},
	{"Anthropic", netip.MustParsePrefix("2607:6bc0::/32")},
	// Microsoft/Azure.
	{"Azure", netip.MustParsePrefix("20.0.0.0/8")},
	{"Azure", netip.MustParsePrefix("40.64.0.0/10")},
	{"Azure", netip.MustParsePrefix("2603:1000::/24")},
	{"Azure", netip.MustParsePrefix("2603:1030::/24")},
	// Fastly.
	{"Fastly", netip.MustParsePrefix("151.101.0.0/16")},
	{"Fastly", netip.MustParsePrefix("2a04:4e40::/32")},
}

// infraSuffixes: PTR-style hostname suffixes → org. Matched on the dot
// boundary so evil-1e100.net.attacker.com cannot spoof membership.
var infraSuffixes = []struct {
	suffix string
	org    string
}{
	{".1e100.net", "Google"},
	{".googleapis.com", "Google"},
	{".google.com", "Google"},
	{".gstatic.com", "Google"},
	{".compute-1.amazonaws.com", "AWS"},
	{".amazonaws.com", "AWS"},
	{".cloudfront.net", "AWS CloudFront"},
	{".aws.dev", "AWS"},
	{".akamai.net", "Akamai"},
	{".akamaiedge.net", "Akamai"},
	{".akamaitechnologies.com", "Akamai"},
	{".fastly.net", "Fastly"},
	{".github.com", "GitHub"},
	{".githubusercontent.com", "GitHub"},
	{".azure.com", "Azure"},
	{".trafficmanager.net", "Azure"},
	{".cloudapp.net", "Azure"},
	{".cloudflare.com", "Cloudflare"},
	{".anthropic.com", "Anthropic"},
	{".openai.com", "OpenAI"},
	{".oaistatic.com", "OpenAI"},
	{".oaiusercontent.com", "OpenAI"},
}

// providerSuffixes is the broader "who owns this?" table used only by
// Identify (the endpoint detail surface). It is intentionally wider than
// infraSuffixes: a VM hostname like *.googleusercontent.com or a registry
// like npmjs.org tells the operator where a connection goes — enough to not
// block rightful work — even though we do NOT collapse those into the
// coverage headline (they are not the agent's own API carrier).
var providerSuffixes = []struct {
	suffix string
	org    string
}{
	{".googleusercontent.com", "Google Cloud"},
	{".gvt1.com", "Google"},
	{".npmjs.org", "npm registry"},
	{".npmjs.com", "npm registry"},
	{".pypi.org", "PyPI"},
	{".pythonhosted.org", "PyPI"},
	{".rubygems.org", "RubyGems"},
	{".crates.io", "crates.io"},
	{".docker.io", "Docker Hub"},
	{".docker.com", "Docker"},
	{".ghcr.io", "GitHub Container Registry"},
	{".gcr.io", "Google Container Registry"},
	{".amazonaws.com", "AWS"},
	{".cloudfront.net", "AWS CloudFront"},
	{".fastly.net", "Fastly"},
	{".cloudflare.com", "Cloudflare"},
	{".microsoft.com", "Microsoft"},
	{".msftconnecttest.com", "Microsoft"},
	{".ubuntu.com", "Ubuntu"},
	{".debian.org", "Debian"},
	{".vercel.com", "Vercel"},
	{".netlify.app", "Netlify"},
	{".sentry.io", "Sentry"},
	{".posthog.com", "PostHog"},
	{".statsig.com", "Statsig"},
	{".segment.io", "Segment"},
	{".amplitude.com", "Amplitude"},
}

func providerBySuffix(h string) string {
	for _, s := range providerSuffixes {
		if strings.HasSuffix(h, s.suffix) {
			return s.org
		}
	}
	return ""
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

// EndpointIdentity is a human-readable answer to "what is this endpoint?" —
// the endpoint detail surface uses it so an IPv6 literal is not an
// unidentifiable address that invites blocking a rightful connection.
type EndpointIdentity struct {
	Org  string `json:"org,omitempty"`  // Cloudflare, Google Cloud, AWS, …
	Name string `json:"name,omitempty"` // a PTR/hostname when one resolves
	Kind string `json:"kind"`           // "ipv4" | "ipv6" | "hostname"
	IP   string `json:"ip,omitempty"`   // the literal address when the host IS an IP
}

// Identify returns the endpoint's identity: its kind, the owning org when
// known, and a resolved name when the address is a bare IP. Best-effort and
// cached; never blocks long (a pointer lookup is time-bounded).
func Identify(host string) EndpointIdentity {
	return identify(host, ptrOrgName)
}

// IdentifyCached is Identify without the network: bare IPs consult the CIDR
// table and whatever the PTR cache already holds, never the resolver. For
// list stamping, where a lookup per row would stall the response.
func IdentifyCached(host string) EndpointIdentity {
	return identify(host, ptrCached)
}

// ptrCached returns the cached PTR result for ip, or empty when none is held.
func ptrCached(ip string) ptrResult {
	if v, ok := ptrCache.Load(ip); ok {
		e := v.(ptrEntry)
		return ptrResult{Org: e.org, Name: e.name}
	}
	return ptrResult{}
}

func identify(host string, ptrLookup func(string) ptrResult) EndpointIdentity {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return EndpointIdentity{Kind: "unknown"}
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		id := EndpointIdentity{Kind: "ipv4", IP: h}
		if ip.Is6() {
			id.Kind = "ipv6"
		}
		for _, r := range providerCIDRs {
			if r.prefix.Contains(ip) {
				id.Org = r.org
				break
			}
		}
		if ptr := ptrLookup(h); ptr.Name != "" {
			id.Name = ptr.Name
			if id.Org == "" {
				id.Org = ptr.Org
			}
			// The PTR name may carry a provider suffix even when the IP is
			// outside our CIDR rules (VM hostnames); use it for identification
			// without affecting the coverage-headline classification.
			if id.Org == "" {
				id.Org = providerBySuffix(strings.ToLower(ptr.Name))
			}
		}
		return id
	}
	return EndpointIdentity{Kind: "hostname", Name: h,
		Org: firstNonEmpty(infraBySuffix(h), providerBySuffix(h))}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
