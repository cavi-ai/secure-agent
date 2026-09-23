package firewall

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"

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
	WouldBlock int    `json:"would_block"`
	Blocked    int    `json:"blocked"`
	Legit      int    `json:"legit"`
	Suspect    int    `json:"suspect"`
	Mode       string `json:"mode"` // effective mode: "monitor" | "block"
	Type       string `json:"type,omitempty"`
}

type Engine struct {
	reg  atomic.Pointer[Registry]
	det  *Detector
	pol  *Policy
	salt []byte

	mu    sync.Mutex
	stats map[string]*RuleStat
}

func NewEngine(cfg config.FirewallConfig, salt []byte) (*Engine, error) {
	det, err := NewDetector(cfg.Patterns, cfg.Entropy)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		det:   det,
		pol:   NewPolicy(cfg),
		salt:  salt,
		stats: map[string]*RuleStat{},
	}
	e.reg.Store(NewRegistry(salt, cfg.Registry.Fingerprints))
	return e, nil
}

// SetFingerprints atomically replaces the known-secret registry, applying
// newly-ingested fingerprints without a restart.
func (e *Engine) SetFingerprints(fps []config.Fingerprint) {
	e.reg.Store(NewRegistry(e.salt, fps))
}

// SetRuleMode changes a rule's mode at runtime (promote monitor -> block, or
// demote). Takes effect on the next Inspect.
func (e *Engine) SetRuleMode(ruleID string, mode Mode) {
	e.pol.SetMode(ruleID, mode)
}

// RuleMode returns the effective mode of a rule.
func (e *Engine) RuleMode(ruleID string) Mode {
	return e.pol.modeFor(ruleID)
}

func patternType(pat config.PatternConfig) string {
	if pat.Type == "" {
		return TypeUnknown
	}
	return pat.Type
}

// RuleIDsOfType returns configured pattern IDs of secretType, sorted.
func (e *Engine) RuleIDsOfType(secretType string) []string {
	var ids []string
	for _, pat := range e.pol.cfg.Patterns {
		if patternType(pat) == secretType {
			ids = append(ids, pat.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

// Stats returns a snapshot of the per-rule tallies, including idle configured
// patterns so the console can promote vendor-key rules before the first hit.
func (e *Engine) Stats() map[string]RuleStat {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string]RuleStat, len(e.pol.cfg.Patterns)+len(e.stats))
	for _, pat := range e.pol.cfg.Patterns {
		s := RuleStat{Type: patternType(pat), Mode: e.pol.modeFor(pat.ID).String()}
		if v := e.stats[pat.ID]; v != nil {
			s.WouldBlock = v.WouldBlock
			s.Blocked = v.Blocked
			s.Legit = v.Legit
			s.Suspect = v.Suspect
		}
		out[pat.ID] = s
	}
	for k, v := range e.stats {
		if _, ok := out[k]; ok {
			continue
		}
		s := *v
		s.Mode = e.pol.modeFor(k).String()
		out[k] = s
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

// ScanText returns the known-secret (fingerprint) and typed-pattern hits in
// free text. No field context, no policy verdict, no tally: callers that are
// not proxying a request (e.g. the transcript tailer) only need the rule ids.
func (e *Engine) ScanText(text string) []Hit {
	if text == "" {
		return nil
	}
	hits := e.reg.Load().Match([]byte(text))
	return append(hits, e.det.Scan(text)...)
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
		for _, h := range e.reg.Load().Match([]byte(text)) {
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
