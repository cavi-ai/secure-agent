package firewall

import (
	"strings"

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

type Engine struct {
	reg *Registry
	det *Detector
	pol *Policy
}

func NewEngine(cfg config.FirewallConfig, salt []byte) (*Engine, error) {
	det, err := NewDetector(cfg.Patterns, cfg.Entropy)
	if err != nil {
		return nil, err
	}
	return &Engine{
		reg: NewRegistry(salt, cfg.Registry.Fingerprints),
		det: det,
		pol: NewPolicy(cfg),
	}, nil
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
	return Decision{Action: action, Findings: findings}
}
