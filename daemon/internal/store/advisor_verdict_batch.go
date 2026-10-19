package store

import "github.com/cavi-ai/secure-agent/daemon/internal/model"

// AdvisorVerdictsFor retains valid advice while reporting one read-health
// result for the whole enrichment batch. Missing advice is not a read failure.
func (s *Store) AdvisorVerdictsFor(subjectIDs []string, kind string) (map[string]model.AdvisorVerdict, error) {
	verdicts, readErr := s.advisorVerdicts(subjectIDs, kind)
	s.noteRead(advisorReadKind(kind), readErr)
	return verdicts, readErr
}
