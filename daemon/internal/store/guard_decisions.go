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

// PutGuardDecision is best effort with a short deadline, so a busy database
// cannot hold the operator's answer behind SQLite's normal busy timeout.
func (s *Store) PutGuardDecision(d GuardDecision) {
	if d.ID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, _ = s.db.ExecContext(ctx, `INSERT OR IGNORE INTO guard_decisions (id, session_id, rule_id, verdict, scope, at) VALUES (?, ?, ?, ?, ?, ?)`,
		d.ID, d.SessionID, d.RuleID, d.Verdict, d.Scope, d.At)
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
