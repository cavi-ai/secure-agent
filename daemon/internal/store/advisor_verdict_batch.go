package store

import "github.com/cavi-ai/secure-agent/daemon/internal/model"

// AdvisorVerdictsFor retains valid advice while reporting one read-health
// result for the whole enrichment batch. Missing advice is not a read failure.
func (s *Store) AdvisorVerdictsFor(subjectIDs []string, kind string) (map[string]model.AdvisorVerdict, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	verdicts := make(map[string]model.AdvisorVerdict, len(subjectIDs))
	seen := make(map[string]struct{}, len(subjectIDs))
	var readErr error
	for _, id := range subjectIDs {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		v, found, err := s.advisorVerdictResultLocked(id, kind)
		if readErr == nil {
			readErr = err
		}
		if found {
			verdicts[id] = v
		}
	}
	s.noteRead(advisorReadKind(kind), readErr)
	return verdicts, readErr
}
