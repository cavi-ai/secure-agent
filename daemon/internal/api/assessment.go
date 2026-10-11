package api

import "github.com/cavi-ai/secure-agent/daemon/internal/model"

// An unknown assessment must not silently lower a detector's priority. Review
// and advice are deliberately absent from this severity calculation.
func assessmentSeverity(a model.FindingAssessment, detectorSeverity int) int {
	switch a.Risk {
	case "critical":
		return 3
	case "high", "review":
		return 2
	case "informational":
		return 1
	default:
		return max(a.DetectorSeverity, detectorSeverity)
	}
}
