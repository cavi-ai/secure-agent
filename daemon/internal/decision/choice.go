// Package decision validates the local classifier's typed choice protocol.
package decision

import "math"

type Answer struct {
	Type          string              `json:"type"`
	Choice        string              `json:"choice"`
	Confidence    *float64            `json:"confidence"`
	Probabilities map[string]*float64 `json:"probabilities"`
}

// Valid checks protocol consistency, not model accuracy or calibration.
func Valid(a Answer, choices []string) bool {
	if a.Type != "choice" || len(a.Probabilities) != len(choices) || len(choices) < 2 || a.Confidence == nil || math.IsNaN(*a.Confidence) || *a.Confidence < 0 || *a.Confidence > 1 {
		return false
	}
	selected := a.Probabilities[a.Choice]
	if selected == nil {
		return false
	}
	validChoice := false
	sum := 0.0
	for _, key := range choices {
		validChoice = validChoice || key == a.Choice
		p, ok := a.Probabilities[key]
		if !ok || p == nil || math.IsNaN(*p) || *p < 0 || *p > 1 || *p > *selected+0.000001 {
			return false
		}
		sum += *p
	}
	uniform := 1 / float64(len(choices))
	expected := math.Max(0, (*selected-uniform)/(1-uniform))
	// The service rounds probabilities and confidence separately to 2 decimals.
	const rounding = 0.005
	return validChoice && math.Abs(sum-1) <= float64(len(choices))*rounding+0.000001 && math.Abs(*a.Confidence-expected) <= rounding+rounding/(1-uniform)+0.000001
}
