package api

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// Test-only reads: a failed read stops the test instead of reading as empty.

func (a *API) computePatterns(since time.Time, min int) []model.Pattern {
	patterns, err := a.computePatternsResult(since, min)
	if err != nil {
		panic(err)
	}
	return patterns
}

func (a *API) routineGroups(since time.Time) []model.RoutineGroup {
	groups, err := a.routineGroupsResult(since)
	if err != nil {
		panic(err)
	}
	return groups
}

func (a *API) suggestionList() []Suggestion {
	suggestions, err := a.suggestionListResult()
	if err != nil {
		panic(err)
	}
	return suggestions
}

func guardDecisionRows(t *testing.T, st *store.Store, sessionID string, limit int) []store.GuardDecision {
	t.Helper()
	rows, err := st.GuardDecisionHistory(sessionID, limit)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}
