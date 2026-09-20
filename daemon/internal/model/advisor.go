package model

import "time"

// AdvisorVerdict is the local advisor's read on a flag or incident. It is
// advisory metadata only — it can never change a rule mode, a guard decision,
// or an enforcement outcome (see docs/ADVISOR_THREAT_MODEL.md).
type AdvisorVerdict struct {
	// Assessment is one of "benign" | "suspicious" | "malicious" (flags only;
	// empty for incident narratives).
	Assessment string  `json:"assessment,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
	// Rationale is the one-line triage reason for a flag, or the narrative
	// paragraph for an incident.
	Rationale       string    `json:"rationale"`
	SuggestedAction string    `json:"suggested_action,omitempty"`
	Model           string    `json:"model,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

// TrendContext is the week-over-week signal the advisor's triage prompt
// carries: is this rule/host new or routine for this machine?
type TrendContext struct {
	RuleLast7d    int    `json:"rule_last_7d"`
	RulePrior7d   int    `json:"rule_prior_7d"`
	HostFirstSeen string `json:"host_first_seen,omitempty"` // RFC3339, empty = never seen
	HostKnown     bool   `json:"host_known"`
}

// GuardAssessmentRequest is what the advisor needs to advise on ONE blocked
// guard prompt. It mirrors the guard.Pending coordinates plus the workspace,
// so the model can reason about intent ("reads .env in a repo that already
// has one committed" vs "reads .ssh/id_rsa from a scratch dir").
//
// The advice is stored and returned as an AdvisorVerdict (kind "guard"): its
// assessment maps to a recommendation — benign → allow, suspicious → unsure,
// malicious → deny. Reusing that shape keeps one parse path and one store
// table, and enforces the same "advisory only" contract.
type GuardAssessmentRequest struct {
	Agent     string `json:"agent"`
	Tool      string `json:"tool"`
	Path      string `json:"path"`
	RuleID    string `json:"rule_id"`
	Workspace string `json:"workspace,omitempty"`
}
