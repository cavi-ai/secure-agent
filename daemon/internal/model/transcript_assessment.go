package model

import (
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/testvalue"
)

func assessTranscript(f Flag, a FindingAssessment) FindingAssessment {
	a.Risk, a.Control, a.ResidualRisk = "high", "observed-only", "possible-exposure"
	a.Reason = "A credential-shaped value was found in saved transcript text. Review whether it is a real credential."
	a.Limits = []string{"Saved transcript text does not establish that a credential was transmitted or accepted by a service."}
	transcripts, testItems := 0, 0
	pattern, other := false, false
	var signals []string
	for _, e := range f.Evidence {
		switch e.Kind {
		case "transcript":
			transcripts++
			if e.Sub == "fingerprint match" {
				a.Risk = "critical"
				a.EvidenceBasis = appendBasis(a.EvidenceBasis, "fingerprint-transcript")
				a.Reason = "A registered secret fingerprint matched saved transcript text."
			}
			pattern = e.Sub == "pattern match" && e.Rule != "" && e.Label != ""
		case "test-value":
			testItems++
			signals = strings.Split(e.Sub, "; ")
		default:
			other = true
		}
	}
	if f.Severity >= 3 {
		a.Risk = "critical"
	}
	if a.Risk == "critical" {
		return a
	}
	if transcripts == 1 && pattern {
		a.EvidenceBasis = []string{"pattern-transcript"}
		if f.Severity == 2 && testItems == 1 && !other && testvalue.LowEntropyTestContext(signals) {
			a.Risk = "review"
			a.EvidenceBasis = append(a.EvidenceBasis, "low-entropy-test-context")
			a.Reason = "A low-entropy credential-shaped value appears in explicit test context. Its validity needs review."
			a.Limits = append(a.Limits, "Low entropy and test context do not establish a dummy value; a weak real credential can still authenticate.")
		}
	}
	return a
}

// TranscriptFindingRisk shares the transcript assessment with reports and
// aggregation. Unrecognized evidence retains high priority.
func TranscriptFindingRisk(f Flag) RiskLevel {
	switch AssessFinding(f).Risk {
	case "critical":
		return RiskCritical
	case "review":
		return RiskMedium
	default:
		return RiskHigh
	}
}

// ProjectTranscriptIncident attaches a current reading without changing the
// recorded summary. A single flag cannot weaken aggregate or rotation evidence.
func ProjectTranscriptIncident(inc IncidentReport, f Flag) IncidentReport {
	if inc.Rule != "secret-in-transcript" || f.Rule != inc.Rule || f.ID != inc.FlagID ||
		f.SessionID != inc.SessionID || f.Agent != inc.Agent || inc.AggregateCount != 1 ||
		len(inc.RotateList) != 0 || (inc.Risk != RiskHigh && inc.Risk != RiskMedium) {
		return inc
	}
	a := AssessFinding(f)
	if a.Risk == "review" {
		inc.Risk = RiskMedium
		inc.Assessment = &a
	}
	return inc
}
