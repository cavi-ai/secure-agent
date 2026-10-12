package store

import (
	"errors"
	"fmt"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

const sessionFindingCap = 20

// SessionFindings is retained findings for one session. Live coverage,
// resource controls, and the activity report are not part of it.
type SessionFindings struct {
	Session   model.Session
	Findings  []SessionFindingEvidence
	Truncated bool
}

// SessionFindingEvidence is one retained finding. The rule is the detector
// id; display titles belong to the console.
type SessionFindingEvidence struct {
	ID         string
	Rule       string
	At         time.Time
	Assessment model.FindingAssessment
}

var (
	ErrSessionFindingsMissing  = errors.New("session not found")
	ErrSessionFindingsIdentity = errors.New("session status unavailable")
	ErrSessionFindingsRead     = errors.New("session findings unavailable")
)

// SessionFindings reads retained findings for a request handler. Identity
// uses the bounded read, so this never waits on the collector mutex. A
// missing session is ErrSessionFindingsMissing. Findings are read only after
// identity succeeds; a findings failure fails the whole read. The result is
// the newest sessionFindingCap findings, with Truncated set when another
// row exists.
func (s *Store) SessionFindings(id string) (SessionFindings, error) {
	sess, found, err := s.GetSessionBounded(id)
	if err != nil {
		return SessionFindings{}, fmt.Errorf("%w: %w", ErrSessionFindingsIdentity, err)
	}
	if !found {
		return SessionFindings{}, ErrSessionFindingsMissing
	}
	flags, err := s.QueryFlagsResult(FlagFilter{SessionID: id, Limit: sessionFindingCap + 1})
	if err != nil {
		return SessionFindings{}, fmt.Errorf("%w: %w", ErrSessionFindingsRead, err)
	}
	n := min(len(flags), sessionFindingCap)
	out := SessionFindings{Session: sess, Findings: make([]SessionFindingEvidence, 0, n), Truncated: len(flags) > sessionFindingCap}
	for _, f := range flags[:n] {
		out.Findings = append(out.Findings, SessionFindingEvidence{ID: f.ID, Rule: f.Rule, At: f.TS, Assessment: model.AssessFinding(f)})
	}
	return out, nil
}

// SessionOutcomeResult is the request-handler read of retained receipts.
// Identity uses the bounded read. Receipt sources then fail independently
// inside the history. Report aggregation already holds identity and calls
// SessionOutcomes directly.
func (s *Store) SessionOutcomeResult(id string) (SessionOutcomeHistory, bool, error) {
	_, found, err := s.GetSessionBounded(id)
	if err != nil || !found {
		return SessionOutcomeHistory{}, found, err
	}
	return s.SessionOutcomes(id), true, nil
}
