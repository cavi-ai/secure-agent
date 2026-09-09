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
