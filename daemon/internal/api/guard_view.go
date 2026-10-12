package api

import (
	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// guardPermissionStore holds the operator's standing guard answers.
type guardPermissionStore interface {
	MatchDecisionScopes([]model.DecisionScope) bool
	GuardPathAllowed(agent, ruleID, path string) bool
	LookupGuardRule(agent, ruleID string) (store.GuardRule, bool)
}

// standingGuardDecision answers from saved permissions, narrowest first: a
// scoped permission for the observed identity, a per-path exception, then the
// agent's rule-wide answer. A rule-wide answer, even a cached deny, never
// overrides a path allow.
func standingGuardDecision(st guardPermissionStore, identity model.DecisionScope, agent, ruleID, path string) (guard.Decision, bool) {
	if identity.IdentityBasis != "" && st.MatchDecisionScopes([]model.DecisionScope{identity}) {
		return guard.Decision{Verdict: "allow", Scope: "scoped", Reason: "saved-permission"}, true
	}
	if st.GuardPathAllowed(agent, ruleID, path) {
		return guard.Decision{Verdict: "allow", Scope: "always", Reason: "path-allow"}, true
	}
	if g, ok := st.LookupGuardRule(agent, ruleID); ok {
		return guard.Decision{Verdict: g.Decision, Scope: "always", Reason: "cached"}, true
	}
	return guard.Decision{}, false
}

// attachGuardAdvice reads advice for every pending prompt in one batch. Advice
// is optional: a failed read leaves prompts unadvised and keeps valid notes.
func attachGuardAdvice(reader advisorVerdictsReader, pending []guard.Pending) {
	subjectIDs := make([]string, len(pending))
	for i, p := range pending {
		subjectIDs[i] = advisor.GuardSubjectID(p.Agent, p.RuleID, p.Path, p.Tool)
	}
	verdicts, _ := reader.AdvisorVerdictsFor(subjectIDs, "guard")
	for i := range pending {
		if v, ok := verdicts[subjectIDs[i]]; ok {
			pending[i].Advisor = &v
		}
	}
}
