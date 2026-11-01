package correlate

import (
	"context"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/hostid"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
)

// The correlator names endpoints with hostid.IdentifyCached, which never
// resolves, but classifies infra with hostid.InfraOrg, which reverse-resolves
// a bare IP outside the infra CIDRs. noPTR makes that lookup answer nothing
// for the rest of t, so identity and infra here come from the CIDR tables
// alone, whatever the machine's resolver says.
func noPTR(t *testing.T) {
	t.Cleanup(hostid.SetLookupAddrForTest(func(context.Context, string) ([]string, error) { return nil, nil }))
}

// Uninspected rows name the vendor the daemon already knows (Anthropic's API
// frontends) while Infra keeps meaning "CDN/cloud carrier" only.
func TestUninspectedSummaryIdentity(t *testing.T) {
	noPTR(t)
	c := newTestCorrelator(t)
	now := time.Now()
	for _, h := range []string{"160.79.104.10", "2607:6bc0::10", "104.16.1.1", "203.0.113.5"} {
		c.Observe(event.Event{Kind: event.KindConnOpen, PID: 200, TS: now, RemoteHost: h, RemotePort: 443})
	}
	got := map[string]UninspectedSummary{}
	for _, s := range c.UninspectedEgressSummary() {
		got[s.Host] = s
	}
	for _, h := range []string{"160.79.104.10", "2607:6bc0::10"} {
		if s := got[h]; s.Identity.Org != "Anthropic" || s.Identity.Class != "vendor" || s.Infra != "" {
			t.Fatalf("%s: identity.org=%q infra=%q, want Anthropic and no infra", h, s.Identity.Org, s.Infra)
		}
	}
	if s := got["104.16.1.1"]; s.Infra != "Cloudflare" || s.Identity.Org != "Cloudflare" {
		t.Fatalf("cloudflare: infra=%q identity.org=%q, want Cloudflare for both", s.Infra, s.Identity.Org)
	}
	if s, ok := got["203.0.113.5"]; !ok || s.Infra != "" || s.Identity.Org != "" {
		t.Fatalf("rfc5737: present=%v infra=%q identity.org=%q, want both empty", ok, s.Infra, s.Identity.Org)
	}
}

// The count-3 advisor pre-assessment skips only the agents' own vendors;
// cloud hosts (which can front anyone) and unknowns are still assessed.
func TestObserveSkipsAdvisorForKnownVendor(t *testing.T) {
	noPTR(t)
	var fired []string
	c := newTestCorrelatorWith(t, Hooks{OnUninspected: func(_, host string) { fired = append(fired, host) }})
	now := time.Now()
	for i := 0; i < 3; i++ {
		for _, h := range []string{"160.79.104.10", "34.120.1.1", "203.0.113.7"} {
			c.Observe(event.Event{Kind: event.KindConnOpen, PID: 200, TS: now, RemoteHost: h, RemotePort: 443})
		}
	}
	if !slices.Equal(fired, []string{"34.120.1.1", "203.0.113.7"}) {
		t.Fatalf("advisor hook fired for %v, want [34.120.1.1 203.0.113.7]", fired)
	}
}

// infraAppSource: an agent (cursor-agent, 200) and an infra app (the Cursor
// IDE, 300) in one process table.
type infraAppSource struct{}

var infraAppProcs = []agents.ProcInfo{
	{PID: 200, PPID: 1, Exe: "/usr/local/bin/cursor-agent"},
	{PID: 300, PPID: 1, Exe: "/Applications/Cursor.app/Contents/MacOS/Cursor"},
}

func (infraAppSource) List() []agents.ProcInfo { return infraAppProcs }

func (infraAppSource) Info(pid int32) (agents.ProcInfo, bool) {
	for _, p := range infraAppProcs {
		if p.PID == pid {
			return p, true
		}
	}
	return agents.ProcInfo{}, false
}

// An infra family's endpoint (an IDE, the Claude app) is listed with
// AgentKind infra and counted in the infrastructure figure, never in the
// agent headline.
func TestInfraAppEgressLeavesTheHeadline(t *testing.T) {
	noPTR(t)
	cfg, err := config.Load("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	tg := agents.New(cfg, infraAppSource{})
	tg.Refresh()
	c := New(tg, sensitive.New(cfg), cfg, Hooks{})
	now := time.Now()
	c.Observe(event.Event{Kind: event.KindConnOpen, PID: 300, TS: now, RemoteHost: "203.0.113.9", RemotePort: 443})
	c.Observe(event.Event{Kind: event.KindConnOpen, PID: 200, TS: now, RemoteHost: "203.0.113.5", RemotePort: 443})

	if got := c.UninspectedEgressCountWindow(UninspectedWindow); got != 1 {
		t.Errorf("headline = %d, want 1 (the agent's endpoint)", got)
	}
	if got := c.UninspectedInfraCountWindow(UninspectedWindow); got != 1 {
		t.Errorf("infrastructure = %d, want 1 (the IDE's endpoint)", got)
	}
	kinds := map[string]string{}
	for _, s := range c.UninspectedEgressSummary() {
		kinds[s.Agent+"|"+s.Host] = s.AgentKind
	}
	if want := map[string]string{"cursor-ide|203.0.113.9": config.AgentKindInfra, "cursor|203.0.113.5": ""}; !maps.Equal(kinds, want) {
		t.Errorf("agent kinds = %v, want %v", kinds, want)
	}
}
