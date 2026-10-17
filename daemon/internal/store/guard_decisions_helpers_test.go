package store

// ListGuardDecisions is a test-only read: a failed read panics instead of
// reading as empty history.
func (s *Store) ListGuardDecisions(sessionID string, limit int) []GuardDecision {
	rows, err := s.GuardDecisionHistory(sessionID, limit)
	if err != nil {
		panic(err)
	}
	return rows
}
