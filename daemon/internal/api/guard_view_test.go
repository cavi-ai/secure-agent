package api

import (
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type memoryGuardPermissions struct {
	scoped  bool
	paths   map[string]bool
	rules   map[string]store.GuardRule
	matched [][]model.DecisionScope
}

func (s *memoryGuardPermissions) MatchDecisionScopes(q []model.DecisionScope) bool {
	s.matched = append(s.matched, q)
	return s.scoped
}

func (s *memoryGuardPermissions) GuardPathAllowed(agent, ruleID, path string) bool {
	return s.paths[agent+"|"+ruleID+"|"+path]
}

func (s *memoryGuardPermissions) LookupGuardRule(agent, ruleID string) (store.GuardRule, bool) {
	g, ok := s.rules[agent+"|"+ruleID]
	return g, ok
}

func TestStandingGuardDecisionNarrowestFirst(t *testing.T) {
	const agent, rule, path = "codex", "ssh-keys", "/home/u/.ssh/config"
	observed := model.DecisionScope{Agent: agent, IdentityBasis: "observed-session", RuleID: rule, ResourcePath: path}
	pathAllow := map[string]bool{agent + "|" + rule + "|" + path: true}
	cachedDeny := map[string]store.GuardRule{agent + "|" + rule: {Agent: agent, RuleID: rule, Decision: "deny"}}
	for _, tc := range []struct {
		name     string
		st       memoryGuardPermissions
		identity model.DecisionScope
		want     guard.Decision
		found    bool
	}{
		{"scoped permission first", memoryGuardPermissions{scoped: true, paths: pathAllow, rules: cachedDeny}, observed,
			guard.Decision{Verdict: "allow", Scope: "scoped", Reason: "saved-permission"}, true},
		{"unobserved identity skips scoped permissions", memoryGuardPermissions{scoped: true, rules: cachedDeny}, model.DecisionScope{},
			guard.Decision{Verdict: "deny", Scope: "always", Reason: "cached"}, true},
		{"path allow beats cached deny", memoryGuardPermissions{paths: pathAllow, rules: cachedDeny}, observed,
			guard.Decision{Verdict: "allow", Scope: "always", Reason: "path-allow"}, true},
		{"cached rule", memoryGuardPermissions{rules: cachedDeny}, observed,
			guard.Decision{Verdict: "deny", Scope: "always", Reason: "cached"}, true},
		{"no standing answer", memoryGuardPermissions{}, observed, guard.Decision{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, found := standingGuardDecision(&tc.st, tc.identity, nil, agent, rule, path)
			if !reflect.DeepEqual(got, tc.want) || found != tc.found {
				t.Fatalf("decision = %+v %v, want %+v %v", got, found, tc.want, tc.found)
			}
			if tc.identity.IdentityBasis == "" && len(tc.st.matched) != 0 {
				t.Fatalf("unobserved identity consulted scoped permissions: %+v", tc.st.matched)
			}
			if tc.identity.IdentityBasis != "" && (len(tc.st.matched) != 1 || len(tc.st.matched[0]) != 1 || tc.st.matched[0][0] != tc.identity) {
				t.Fatalf("scoped permissions asked about %+v, want [%+v]", tc.st.matched, tc.identity)
			}
		})
	}
}

func TestGuardAdviceBatchKeepsValidNotesOnFailure(t *testing.T) {
	pending := []guard.Pending{
		{ID: "a", Agent: "codex", RuleID: "ssh-keys", Path: "/k", Tool: "Read"},
		{ID: "b", Agent: "claude", RuleID: "env-files", Path: "/w/.env", Tool: "Edit"},
	}
	r := &memoryAdvisorVerdicts{err: errors.New("advice unavailable"), verdicts: map[string]model.AdvisorVerdict{
		"guard:claude|env-files|Edit|/w/.env": {Assessment: "risky", Rationale: "Secret file"},
	}}
	attachGuardAdvice(r, pending)
	if r.reads != 1 || r.kind != "guard" || !slices.Equal(r.ids, []string{"guard:codex|ssh-keys|Read|/k", "guard:claude|env-files|Edit|/w/.env"}) {
		t.Fatalf("advice batch: %+v", r)
	}
	if pending[0].Advisor != nil || pending[1].Advisor == nil || pending[1].Advisor.Assessment != "risky" {
		t.Fatalf("advice attached to the wrong prompts: %+v", pending)
	}
}
