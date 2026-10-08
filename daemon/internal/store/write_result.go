package store

import "github.com/cavi-ai/secure-agent/daemon/internal/event"

// WriteResult distinguishes a changed SQLite row from a deduplicated
// observation. HealthChanged also covers independent mirror failures.
// Upserts retain their existing merge rules; Changed is not a replacement
// guarantee for every incoming field.
type WriteResult struct {
	Changed       bool
	HealthChanged bool
}

// eventNoopStoredLocked verifies the two intentional zero-row write cases.
// A silently ignored new insert must not be mistaken for a stored duplicate.
func (s *Store) eventNoopStoredLocked(e event.Event, timestamp string) (bool, error) {
	var exists bool
	var err error
	switch {
	case e.Kind == event.KindModelCall && e.CallID != "":
		err = s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM events
			WHERE kind=? AND session_id=? AND call_id=?
			AND COALESCE(tokens_in,0)>=? AND COALESCE(tokens_out,0)>=? AND COALESCE(cost_usd,0)>=?)`,
			int(e.Kind), e.SessionID, e.CallID, e.TokensIn, e.TokensOut, e.CostUSD).Scan(&exists)
	case e.Kind == event.KindTurn && e.CallID == "":
		err = s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM events WHERE kind=? AND session_id=? AND ts=?)`,
			int(e.Kind), e.SessionID, timestamp).Scan(&exists)
	}
	return exists, err
}
