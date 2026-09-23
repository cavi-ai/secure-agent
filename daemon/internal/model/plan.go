package model

import "time"

// PlanStep is one prevention measure in an advisor plan. Kind is guard-rule,
// config, secret-hygiene, agent-instruction or workflow.
type PlanStep struct {
	Kind   string `json:"kind"`
	Step   string `json:"step"`
	Detail string `json:"detail"`
}

// AdvisorPlan is the local advisor's plan for one subject (a flag, an
// incident or an evidence file): why it happens, how to prevent it, behavior
// changes and remediation. Actions are served action ids the operator can
// click. EvidenceKey fingerprints the evidence the plan was written from;
// a different key today means the plan is stale.
type AdvisorPlan struct {
	Summary     string     `json:"summary"`
	Why         []string   `json:"why"`
	Risk        string     `json:"risk"` // low | medium | high
	Prevent     []PlanStep `json:"prevent"`
	Behavior    []string   `json:"behavior"`
	Remediate   []string   `json:"remediate"`
	Actions     []string   `json:"actions"`
	Confidence  float64    `json:"confidence"`
	Model       string     `json:"model,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	EvidenceKey string     `json:"evidence_key"`
}
