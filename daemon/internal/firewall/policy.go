package firewall

import (
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

type Policy struct {
	cfg        config.FirewallConfig
	ruleMode   map[string]Mode
	globalMode Mode
}

func NewPolicy(cfg config.FirewallConfig) *Policy {
	p := &Policy{cfg: cfg, ruleMode: map[string]Mode{}, globalMode: ParseMode(cfg.Mode)}
	for _, pat := range cfg.Patterns {
		p.ruleMode[pat.ID] = ParseMode(pat.Mode)
	}
	return p
}

func (p *Policy) modeFor(ruleID string) Mode {
	if m, ok := p.ruleMode[ruleID]; ok {
		return m
	}
	return p.globalMode
}

// Classify decides whether a hit in a given request context is a leak, and what
// action follows. Entropy hits are always suspect and never block.
func (p *Policy) Classify(h Hit, ctx RequestCtx) Verdict {
	if h.Layer == LayerEntropy {
		return Verdict{Kind: VerdictSuspect, Mode: p.modeFor(h.RuleID), Action: ActionAllow}
	}

	// Legitimate: a vendor's own credential in its expected auth header to one
	// of its allowlisted hosts.
	if p.cfg.Context.AllowOwnVendorAuth && ctx.Field == FieldAuthHeader && p.isVendorHost(ctx.Agent, ctx.Host) {
		return Verdict{Kind: VerdictLegit, Mode: p.modeFor(h.RuleID), Action: ActionAllow}
	}

	// Otherwise a fingerprint/pattern hit is a leak: foreign host, or a secret in
	// a body/query/other-header where credentials do not belong.
	leak := false
	if !p.isVendorHost(ctx.Agent, ctx.Host) {
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
