package firewall

import (
	"strings"
	"sync"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

type Request struct {
	Agent          string
	Host           string
	Query          string
	AuthHeaderName string
	Headers        map[string]string
	Body           []byte
}

// RuleStat is the running per-rule tally used to decide whether a rule is safe
// to promote from monitor to block. A rule with many WouldBlock and zero
// operator-confirmed false positives is a promotion candidate.
type RuleStat struct {
	WouldBlock int `json:"would_block"`
	Blocked    int `json:"blocked"`
	Legit      int `json:"legit"`
	Suspect    int `json:"suspect"`
}

type Engine struct {
	reg *Registry
	det *Detector
	pol *Policy

	mu    sync.Mutex
	stats map[string]*RuleStat
}

func NewEngine(cfg config.FirewallConfig, salt []byte) (*Engine, error) {
	det, err := NewDetector(cfg.Patterns, cfg.Entropy)
	if err != nil {
		return nil, err
	}
	return &Engine{
		reg:   NewRegistry(salt, cfg.Registry.Fingerprints),
		det:   det,
		pol:   NewPolicy(cfg),
		stats: map[string]*RuleStat{},
	}, nil
}

// Stats returns a snapshot of the per-rule tallies.
func (e *Engine) Stats() map[string]RuleStat {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string]RuleStat, len(e.stats))
	for k, v := range e.stats {
		out[k] = *v
	}
	return out
}

func (e *Engine) tally(findings []Finding) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, f := range findings {
		s := e.stats[f.Hit.RuleID]
		if s == nil {
			s = &RuleStat{}
			e.stats[f.Hit.RuleID] = s
		}
		switch f.Verdict.Kind {
		case VerdictLeak:
			if f.Verdict.Action == ActionBlock {
				s.Blocked++
			} else {
				s.WouldBlock++
			}
		case VerdictLegit:
			s.Legit++
		case VerdictSuspect:
			s.Suspect++
		}
	}
}

// Inspect scans each field of the request, classifies every hit in its field
// context, and resolves the strongest action. Callers treat the returned
// Decision as authoritative and otherwise fail open.
func (e *Engine) Inspect(req Request) Decision {
	var findings []Finding

	scanField := func(text string, field Field) {
		if text == "" {
			return
		}
		ctx := RequestCtx{Agent: req.Agent, Host: req.Host, Field: field}
		for _, h := range e.reg.Match([]byte(text)) {
			findings = append(findings, Finding{Hit: h, Ctx: ctx, Verdict: e.pol.Classify(h, ctx)})
		}
		for _, h := range e.det.Scan(text) {
			findings = append(findings, Finding{Hit: h, Ctx: ctx, Verdict: e.pol.Classify(h, ctx)})
		}
	}

	authName := strings.ToLower(req.AuthHeaderName)
	for name, val := range req.Headers {
		field := FieldOtherHeader
		if authName != "" && strings.ToLower(name) == authName {
			field = FieldAuthHeader
		}
		scanField(val, field)
	}
	scanField(req.Query, FieldQuery)
	scanField(string(req.Body), FieldBody)

	action := ActionAllow
	for _, f := range findings {
		if f.Verdict.Action > action { // ActionAllow < ActionWouldBlock < ActionBlock
			action = f.Verdict.Action
		}
	}
	e.tally(findings)
	return Decision{Action: action, Findings: findings}
}
