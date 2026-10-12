package store

import "time"

// RuleCounts distinguishes a healthy empty history from a failed read.
// Failed reads return no partial counts.
func (s *Store) RuleCounts(rule, agent string, now time.Time) (last7, last30 int, readErr error) {
	defer func() { s.noteRead("rule history", readErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	d7 := instantArg(now.Add(-7 * 24 * time.Hour))
	d30 := instantArg(now.Add(-30 * 24 * time.Hour))
	if err := s.db.QueryRow(ruleCountsSQL, d7, d30, rule, agent).Scan(&last7, &last30); err != nil {
		return 0, 0, err
	}
	return last7, last30, nil
}
