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
	pattern    bool
	WouldBlock int    `json:"would_block"`
	Blocked    int    `json:"blocked"`
	Legit      int    `json:"legit"`
	Suspect    int    `json:"suspect"`
	Mode       string `json:"mode"` // effective mode: "monitor" | "block"
	Type       string `json:"type,omitempty"`
}

type Engine struct {
	reg      atomic.Pointer[Registry]
	configMu sync.RWMutex
	det      *Detector
	pol      *Policy
	salt     []byte

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
	e.configMu.RLock()
	defer e.configMu.RUnlock()
	e.pol.SetMode(ruleID, mode)
}

// RuleMode returns the effective mode of a rule.
func (e *Engine) RuleMode(ruleID string) Mode {
	_, pol := e.policySnapshot()
	return pol.modeFor(ruleID)
}

func (e *Engine) policySnapshot() (*Detector, *Policy) {
	e.configMu.RLock()
	defer e.configMu.RUnlock()
	return e.det, e.pol
}

// Patterns returns a detached copy, with current mode overrides applied.
func (e *Engine) Patterns() []config.PatternConfig {
	_, pol := e.policySnapshot()
	patterns := append([]config.PatternConfig{}, pol.cfg.Patterns...)
	for i := range patterns {
		patterns[i].Mode = pol.modeFor(patterns[i].ID).String()
	}
	return patterns
}

// ReplacePatterns compiles and persists before swapping the running detector.
// Existing streaming inspections retain their policy snapshot for consistency.
func (e *Engine) ReplacePatterns(patterns []config.PatternConfig, persist func() error) error {
	if err := config.ValidateFirewallPatterns(patterns); err != nil {
		return err
	}
	e.configMu.Lock()
	defer e.configMu.Unlock()
	cfg := e.pol.cfg
	cfg.Patterns = append([]config.PatternConfig{}, patterns...)
	det, err := NewDetector(cfg.Patterns, cfg.Entropy)
	if err != nil {
		return err
	}
	pol := NewPolicy(cfg)
	e.pol.mu.RLock()
	for id, mode := range e.pol.ruleMode {
		pol.ruleMode[id] = mode
	}
	e.pol.mu.RUnlock()
	// The pattern editor changes detection, while /firewall/mode owns modes.
	if err := persist(); err != nil {
		return err
	}
	e.det, e.pol = det, pol
	return nil
}

func patternType(pat config.PatternConfig) string {
	if pat.Type == "" {
		return TypeUnknown
	}
	return pat.Type
}

// RuleIDsOfType returns configured pattern IDs of secretType, sorted.
func (e *Engine) RuleIDsOfType(secretType string) []string {
	_, pol := e.policySnapshot()
	var ids []string
	for _, pat := range pol.cfg.Patterns {
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
	_, pol := e.policySnapshot()
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string]RuleStat, len(pol.cfg.Patterns)+len(e.stats))
	for _, pat := range pol.cfg.Patterns {
		s := RuleStat{Type: patternType(pat), Mode: pol.modeFor(pat.ID).String()}
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
		if v.pattern {
			continue
		}
		s := *v
		s.Mode = pol.modeFor(k).String()
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
		s.pattern = f.Hit.Layer == LayerPattern
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

// Mask returns text with every typed-pattern and fingerprint hit replaced by
// [REDACTED:<rule id>], and whether a rescan of the result is clean. A secret
// the rescan still finds (one present only encoded, matched in a decoded view)
// leaves clean false: callers withhold the text rather than show it.
func (e *Engine) Mask(text string) (string, bool) {
	det, _ := e.policySnapshot()
	reg := e.reg.Load()
	masked := reg.MaskTokens(det.MaskPatterns(text))
	return masked, len(reg.Match([]byte(masked))) == 0 && len(det.ScanPatterns(masked)) == 0
}

// ScanText returns the known-secret (fingerprint) and typed-pattern hits in
// free text. The entropy layer is not run, and there is no field context, no
// policy verdict and no tally: callers that are not proxying a request (e.g.
// the transcript tailer) only need the rule ids.
func (e *Engine) ScanText(text string) []Hit {
	if text == "" {
		return nil
	}
	hits := e.reg.Load().Match([]byte(text))
	det, _ := e.policySnapshot()
	return append(hits, det.ScanPatterns(text)...)
}

// Inspect scans each field of the request, classifies every hit in its field
// context, and resolves the strongest action. Callers treat the returned
// Decision as authoritative and otherwise fail open.
func (e *Engine) Inspect(req Request) Decision {
	dec := e.inspect(req)
	e.tally(dec.Findings)
	return dec
}

func (e *Engine) inspect(req Request) Decision {
	det, pol := e.policySnapshot()
	return inspectWith(req, e.reg.Load(), det, pol)
}

func inspectWith(req Request, reg *Registry, det *Detector, pol *Policy) Decision {
	var findings []Finding

	scanField := func(text string, field Field) {
		if text == "" {
			return
		}
		ctx := RequestCtx{Agent: req.Agent, Host: req.Host, Field: field}
		for _, h := range reg.Match([]byte(text)) {
			findings = append(findings, Finding{Hit: h, Ctx: ctx, Verdict: pol.Classify(h, ctx)})
		}
		for _, h := range det.Scan(text) {
			findings = append(findings, Finding{Hit: h, Ctx: ctx, Verdict: pol.Classify(h, ctx)})
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
	return Decision{Action: action, Findings: findings}
}
