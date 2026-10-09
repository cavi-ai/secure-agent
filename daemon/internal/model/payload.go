package model

import "fmt"

// PayloadEvidence records the local proxy's resolved request gate separately
// from a match's own policy action. It carries no matched bytes or headers.
type PayloadEvidence struct {
	Layer         string `json:"layer"`
	Field         string `json:"field"`
	Verdict       string `json:"verdict"`
	FindingAction string `json:"finding_action"`
	RequestAction string `json:"request_action"`
}

// IsLeak requires a supported detector and consistent resolved actions.
// Entropy is a heuristic, never evidence of a confirmed secret or a block.
func (p PayloadEvidence) IsLeak() bool {
	if p.Layer != "fingerprint" && p.Layer != "pattern" || p.Verdict != "leak" {
		return false
	}
	switch p.Field {
	case "auth-header", "other-header", "query", "body":
	default:
		return false
	}
	return (p.FindingAction == "block" && p.RequestAction == "block") ||
		(p.FindingAction == "would-block" && (p.RequestAction == "block" || p.RequestAction == "would-block"))
}

// PayloadOutcomeSummary counts distinct recorded findings, not requests or
// delivered payloads. It survives source retention through the incident JSON.
type PayloadOutcomeSummary struct {
	Blocked      int `json:"blocked"`
	ObservedOnly int `json:"observed_only"`
	Unknown      int `json:"unknown"`
}

func PayloadOutcomeForFinding(f Flag) *PayloadOutcomeSummary {
	if f.Rule != "proxy-secret-leak" {
		return nil
	}
	out := &PayloadOutcomeSummary{}
	switch AssessFinding(f).Control {
	case "blocked":
		out.Blocked = 1
	case "observed-only":
		out.ObservedOnly = 1
	default:
		out.Unknown = 1
	}
	return out
}

func (p PayloadOutcomeSummary) Summary() string {
	return fmt.Sprintf("Recorded payload findings: %d blocked before forwarding; %d observed only; %d outcome unknown. These counts cover recorded findings, not every request. Observation does not establish delivery. Earlier exposure and external credential revocation are not verified.", p.Blocked, p.ObservedOnly, p.Unknown)
}
