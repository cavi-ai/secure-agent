package store

import "time"

// RuleCountsResult distinguishes a healthy empty history from a failed read.
// Failed reads return no partial counts.
func (s *Store) RuleCountsResult(rule, agent string, now time.Time) (last7, last30 int, readErr error) {
	defer func() { s.noteRead("rule history", readErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	d7 := now.Add(-7 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	d30 := now.Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	if err := s.db.QueryRow(ruleCountsSQL, d7, d30, rule, agent).Scan(&last7, &last30); err != nil {
		return 0, 0, err
	}
	return last7, last30, nil
}
