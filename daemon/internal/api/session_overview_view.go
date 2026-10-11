package api

import (
	"errors"
	"fmt"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

var (
	errSessionOverviewStatus   = errors.New("session status unavailable")
	errSessionOverviewMissing  = errors.New("session not found")
	errSessionOverviewFindings = errors.New("session findings unavailable")
)

type sessionOverviewStore interface {
	GetSessionResult(string) (model.Session, bool, error)
	QueryFlagsResult(store.FlagFilter) ([]model.Flag, error)
}

type sessionOverviewEvidence struct {
	Session   model.Session
	Findings  []SessionFinding
	Truncated bool
}

// readSessionOverviewEvidence selects retained evidence by durable session ID.
// Live coverage and controls are gathered separately by the HTTP boundary.
func readSessionOverviewEvidence(st sessionOverviewStore, id string) (sessionOverviewEvidence, error) {
	sess, found, err := st.GetSessionResult(id)
	if err != nil {
		return sessionOverviewEvidence{}, fmt.Errorf("%w: %w", errSessionOverviewStatus, err)
	}
	if !found {
		return sessionOverviewEvidence{}, errSessionOverviewMissing
	}
	const findingCap = 20
	flags, err := st.QueryFlagsResult(store.FlagFilter{SessionID: id, Limit: findingCap + 1})
	if err != nil {
		return sessionOverviewEvidence{}, fmt.Errorf("%w: %w", errSessionOverviewFindings, err)
	}
	out := sessionOverviewEvidence{Session: sess, Findings: []SessionFinding{}, Truncated: len(flags) > findingCap}
	for _, f := range flags[:min(len(flags), findingCap)] {
		out.Findings = append(out.Findings, SessionFinding{ID: f.ID, Title: memoryRuleTitle(f.Rule), At: f.TS, Assessment: model.AssessFinding(f)})
	}
	return out, nil
}
