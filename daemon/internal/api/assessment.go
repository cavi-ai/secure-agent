package api

import "github.com/cavi-ai/secure-agent/daemon/internal/model"

func assessmentForFlag(f model.Flag) model.FindingAssessment { return model.AssessFinding(f) }

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

// A grouped card qualifies its strongest member rather than treating repeated
// observations or an acknowledgment as evidence of safety.
func assessmentForFlags(flags []model.Flag) *model.FindingAssessment {
	var strongest *model.FindingAssessment
	rank, open := -1, false
	for _, f := range flags {
		a := assessmentForFlag(f)
		if !f.Acknowledged {
			open = true
		}
		if severity := assessmentSeverity(a, f.Severity); severity > rank || (severity == rank && strongest != nil && strongest.Risk == "unknown" && a.Risk != "unknown") {
			strongest, rank = &a, severity
		}
	}
	if strongest != nil {
		if open {
			strongest.ReviewState = "unreviewed"
		} else {
			strongest.ReviewState = "reviewed"
		}
		strongest.Limits = append(strongest.Limits, "This assessment describes the strongest member; grouped activity does not establish shared intent.")
	}
	return strongest
}
