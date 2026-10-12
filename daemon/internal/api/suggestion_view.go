package api

import (
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

type suggestionVerdictReader interface {
	AdvisorVerdictsFor([]string, string) (map[string]model.AdvisorVerdict, error)
}

// readEgressSuggestions selects recurring endpoints that need a decision.
// Advisor failures retain observed endpoints and valid sibling verdicts.
func readEgressSuggestions(reader suggestionVerdictReader, endpoints []correlate.UninspectedSummary) ([]Suggestion, error) {
	out := []Suggestion{}
	for _, e := range endpoints {
		if e.Count < minSuggestionCount || e.Infra != "" || e.Identity.Class == "vendor" || e.AgentKind == config.AgentKindInfra {
			continue
		}
		out = append(out, Suggestion{Agent: e.Agent, Host: e.Host, Count: e.Count, Identity: e.Identity})
	}
	ids := make([]string, len(out))
	for i, sg := range out {
		ids[i] = "host:" + sg.Agent + "|" + sg.Host
	}
	verdicts, readErr := reader.AdvisorVerdictsFor(ids, "host")
	for i, id := range ids {
		if v, ok := verdicts[id]; ok {
			out[i].Assessment = v.Assessment
			out[i].Rationale = v.Rationale
			out[i].Confidence = v.Confidence
		}
	}
	return out, readErr
}
