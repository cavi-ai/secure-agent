package api

import (
	"fmt"
	"math"
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// benignConfidence is the advisor confidence at which a "benign" assessment
// turns a flag's disposition into benign-likely.
const benignConfidence = 0.85

// dispositionFor is the one verdict every surface renders for a flag, in
// precedence order: the operator's acknowledgement, then a confident benign
// advisor assessment, then the rule severity. Advisory input only changes how
// the flag is presented, never what the rule detects or enforces.
func dispositionFor(f model.Flag) model.Disposition {
	switch {
	case f.Acknowledged:
		return model.Disposition{State: model.DispositionAcknowledged, Text: "Reviewed", Why: humanFlagTitle(f.Rule)}
	case f.Advisor != nil && f.Advisor.Assessment == "benign" && f.Advisor.Confidence >= benignConfidence:
		return model.Disposition{
			State: model.DispositionBenignLikely,
			Text:  fmt.Sprintf("Likely benign (advisor %d %%)", int(math.Round(f.Advisor.Confidence*100))),
			Why:   firstSentence(f.Advisor.Rationale),
		}
	case f.Severity >= 3:
		return model.Disposition{State: model.DispositionCritical, Text: "Act now", Why: ruleWhy(f)}
	default:
		return model.Disposition{State: model.DispositionWarning, Text: "Needs a look", Why: ruleWhy(f)}
	}
}

// ruleWhy is an open flag's reason: for read-then-connect, what its evidence
// says about the destination and the file's owner; otherwise the rule title.
func ruleWhy(f model.Flag) string {
	if f.Rule == readConnectRule {
		if why := readConnectWhy(f); why != "" {
			return why
		}
	}
	return humanFlagTitle(f.Rule)
}

// dispositionSeverity is the posture severity a disposition carries.
func dispositionSeverity(d model.Disposition) int {
	switch d.State {
	case model.DispositionCritical:
		return 3
	case model.DispositionWarning:
		return 2
	default:
		return 1
	}
}

// firstSentence is text up to and including the first ". " boundary (or the
// whole text when it has none).
func firstSentence(text string) string {
	text = strings.TrimSpace(text)
	if i := strings.Index(text, ". "); i >= 0 {
		return text[:i+1]
	}
	return text
}
