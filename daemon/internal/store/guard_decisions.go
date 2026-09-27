package store

import (
	"context"
	"time"
)

// GuardDecision is a redacted outcome of one guard request. A path, command,
// and prompt never enter this table.
type GuardDecision struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id,omitempty"`
	RuleID    string `json:"rule_id"`
	Verdict   string `json:"verdict"`
	Scope     string `json:"scope"`
	At        string `json:"at"`
}

const guardDecisionsSchema = `CREATE TABLE IF NOT EXISTS guard_decisions (
	id TEXT PRIMARY KEY,
	session_id TEXT NOT NULL,
	rule_id TEXT NOT NULL,
	verdict TEXT NOT NULL,
	scope TEXT NOT NULL,
	at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_guard_decisions_session_at ON guard_decisions(session_id, at, id);`

const (
	guardDecisionTimeLayout = "2006-01-02T15:04:05.000000000Z"
	maxGuardDecisions       = 10000
	guardDecisionPruneEvery = 256
)

// PutGuardDecision is best effort with a short deadline, so a busy database
// cannot hold the operator's answer behind SQLite's normal busy timeout.
func (s *Store) PutGuardDecision(d GuardDecision) {
	if d.ID == "" {
		return
	}
	at, err := time.Parse(time.RFC3339Nano, d.At)
	if err != nil {
		return
	}
	// Fixed-width UTC sorts by instant in SQLite's TEXT index. RFC3339Nano's
	// variable fractional precision does not.
	d.At = at.UTC().Format(guardDecisionTimeLayout)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO guard_decisions (id, session_id, rule_id, verdict, scope, at) VALUES (?, ?, ?, ?, ?, ?)`,
		d.ID, d.SessionID, d.RuleID, d.Verdict, d.Scope, d.At)
	if err != nil {
		return
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return
	}
	writes := s.guardDecisionWrites.Add(1)
	if writes != 1 && writes%guardDecisionPruneEvery != 0 {
		return
	}
	s.mu.Lock()
	retention := s.eventRetention
	s.mu.Unlock()
	if retention <= 0 {
		retention = DefaultEventRetention
	}
	pruneCtx, pruneCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer pruneCancel()
	_ = s.pruneGuardDecisions(pruneCtx, retention, maxGuardDecisions)
}

// pruneGuardDecisions applies the configured event age limit and a count
// backstop. It runs periodically on guard inserts, including the first insert
// after startup, without holding the store's event publication lock.
func (s *Store) pruneGuardDecisions(ctx context.Context, retention time.Duration, cap int) error {
	cutoff := time.Now().Add(-retention).UTC().Format(guardDecisionTimeLayout)
	_, err := s.db.ExecContext(ctx, `DELETE FROM guard_decisions WHERE at < ? OR id NOT IN (
		SELECT id FROM guard_decisions ORDER BY at DESC, id DESC LIMIT ?)`, cutoff, cap)
	return err
}

// ListGuardDecisions selects only rows explicitly attributed to sessionID.
func (s *Store) ListGuardDecisions(sessionID string, limit int) []GuardDecision {
	if limit <= 0 {
		return nil
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := s.db.Query(`SELECT id, session_id, rule_id, verdict, scope, at FROM guard_decisions WHERE session_id = ? ORDER BY at DESC, id DESC LIMIT ?`, sessionID, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := make([]GuardDecision, 0)
	for rows.Next() {
		var d GuardDecision
		if rows.Scan(&d.ID, &d.SessionID, &d.RuleID, &d.Verdict, &d.Scope, &d.At) == nil {
			out = append(out, d)
		}
	}
	return out
}
