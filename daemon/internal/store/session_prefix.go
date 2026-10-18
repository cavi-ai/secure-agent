package store

import (
	"fmt"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// FindSessionsByPrefix returns up to two retained sessions whose IDs begin
// with prefix, in ascending ID order. Two rows are sufficient for callers to
// distinguish a unique match from an ambiguous prefix.
func (s *Store) FindSessionsByPrefix(prefix string) (out []model.Session, readErr error) {
	defer func() { s.noteRead("sessions", readErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(sessionSelect+` WHERE substr(id, 1, length(?)) = ? ORDER BY id COLLATE BINARY ASC LIMIT 2`, prefix, prefix)
	if err != nil {
		return nil, fmt.Errorf("find sessions by prefix: %w", err)
	}
	sessions, err := scanSessionsResult(rows)
	if err != nil {
		return nil, fmt.Errorf("read sessions by prefix: %w", err)
	}
	if sessions == nil {
		return []model.Session{}, nil
	}
	return sessions, nil
}
