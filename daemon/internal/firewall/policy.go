package firewall

import (
	"strings"
	"sync"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

type Policy struct {
	cfg        config.FirewallConfig
	globalMode Mode

	mu       sync.RWMutex
	ruleMode map[string]Mode // guarded by mu; the only mutable policy state
}

func NewPolicy(cfg config.FirewallConfig) *Policy {
	p := &Policy{cfg: cfg, ruleMode: map[string]Mode{}, globalMode: ParseMode(cfg.Mode)}
	for _, pat := range cfg.Patterns {
		p.ruleMode[pat.ID] = ParseMode(pat.Mode)
	}
	return p
}

func (p *Policy) modeFor(ruleID string) Mode {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if m, ok := p.ruleMode[ruleID]; ok {
		return m
	}
	return p.globalMode
}

// SetMode changes a rule's mode at runtime (e.g. promoting monitor -> block).
func (p *Policy) SetMode(ruleID string, mode Mode) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ruleMode[ruleID] = mode
}

// Classify decides whether a hit in a given request context is a leak, and what
// action follows. Entropy hits are always suspect and never block.
func (p *Policy) Classify(h Hit, ctx RequestCtx) Verdict {
	if h.Layer == LayerEntropy {
		return Verdict{Kind: VerdictSuspect, Mode: p.modeFor(h.RuleID), Action: ActionAllow}
	}

	// Legitimate: a credential in the expected auth header to a vendor host. When
	// the agent is known its own allowlist is used; when it is not (the proxy
	// sees the connection, not the process), any known vendor host qualifies.
	if p.cfg.Context.AllowOwnVendorAuth && ctx.Field == FieldAuthHeader && p.vendorHostMatch(ctx.Agent, ctx.Host) {
		return Verdict{Kind: VerdictLegit, Mode: p.modeFor(h.RuleID), Action: ActionAllow}
	}

	// Otherwise a fingerprint/pattern hit is a leak: foreign host, or a secret in
	// a body/query/other-header where credentials do not belong.
	leak := false
	if !p.vendorHostMatch(ctx.Agent, ctx.Host) {
		leak = true
	}
	if ctx.Field != FieldAuthHeader && p.cfg.Context.TreatBodySecretAsLeak {
		leak = true
	}
	if !leak {
		return Verdict{Kind: VerdictSuspect, Mode: p.modeFor(h.RuleID), Action: ActionAllow}
	}

	mode := p.modeFor(h.RuleID)
	act := ActionWouldBlock
	if mode == ModeBlock {
		act = ActionBlock
	}
	return Verdict{Kind: VerdictLeak, Mode: mode, Action: act}
}

// vendorHostMatch reports whether host is a legitimate destination for a
// credential. With a known agent, only that agent's own vendor hosts count;
// with an unknown agent (proxy context), any configured vendor host counts.
func (p *Policy) vendorHostMatch(agent, host string) bool {
	if agent != "" {
		return p.isVendorHost(agent, host)
	}
	return p.isKnownVendorHost(host)
}

func (p *Policy) isKnownVendorHost(host string) bool {
	for a := range p.cfg.Vendors {
		if p.isVendorHost(a, host) {
			return true
		}
	}
	return false
}

func (p *Policy) isVendorHost(agent, host string) bool {
	v, ok := p.cfg.Vendors[agent]
	if !ok {
		return false
	}
	host = strings.ToLower(host)
	for _, h := range v.Hosts {
		h = strings.ToLower(h)
		if host == h || strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	return false
}
