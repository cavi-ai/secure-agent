package model

// FindingAssessment separates observed risk from operator review and optional
// advice. It is a read model, never an input to detection or enforcement.
type FindingAssessment struct {
	// DetectorSeverity preserves priority for evidence the projection cannot
	// classify. Internal only; clients retain the original flag severity.
	DetectorSeverity int             `json:"-"`
	EvidenceBasis    []string        `json:"evidence_basis"`
	Risk             string          `json:"risk"`
	Control          string          `json:"control"`
	ResidualRisk     string          `json:"residual_risk"`
	ReviewState      string          `json:"review_state"`
	RecommendationID string          `json:"recommendation_id,omitempty"`
	Reason           string          `json:"reason"`
	Limits           []string        `json:"limits"`
	Advice           *AdvisorVerdict `json:"advice,omitempty"`
}
