package store

import (
	"fmt"
	"log"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// hook_runs holds one row per harness hook execution read from a session
// transcript: hook event, the command's script name, outcome, duration and
// the character count it returned, never its text. (session_id, run_id) is
// unique, so a transcript re-read cannot count a run twice. Kept out of
// events so per-tool-call hook volume never crowds session timelines.
const hookRunsSchema = `CREATE TABLE IF NOT EXISTS hook_runs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	session_id TEXT NOT NULL,
	run_id TEXT NOT NULL,
	ts TEXT NOT NULL,
	hook TEXT NOT NULL,
	script TEXT NOT NULL,
	status TEXT NOT NULL,
	duration_ms INTEGER NOT NULL DEFAULT 0,
	chars INTEGER NOT NULL DEFAULT 0,
	UNIQUE(session_id, run_id)
);`

// hookRunBudget caps hook_runs rows. Hooks fire before and after every tool
// call (about 1,500 runs in one long session), so time retention alone does
// not bound the table.
var hookRunBudget = 200000

// HookSummary is one hook's totals in a session, keyed by hook event (without
// the tool it fired for) and the command's script.
type HookSummary struct {
	Event   string `json:"event"`
	Script  string `json:"script"`
	Runs    int64  `json:"runs"`
	Errors  int64  `json:"errors"` // error or cancelled
	Blocks  int64  `json:"blocks"` // deny or block
	Chars   int64  `json:"chars"`
	TotalMs int64  `json:"total_ms"`
	LastAt  string `json:"last_at"`
}

func (s *Store) putHookRunLocked(e event.Event) (WriteResult, error) {
	res, err := s.db.Exec(`INSERT OR IGNORE INTO hook_runs (session_id, run_id, ts, hook, script, status, duration_ms, chars)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		e.SessionID, e.CallID, e.TS.UTC().Format(time.RFC3339Nano), e.ToolName, e.Detail, e.ToolStatus, e.DurationMs, e.Chars)
	var n int64
	if err == nil {
		n, err = res.RowsAffected()
	}
	if err != nil {
		log.Printf("store: failed to insert hook run: %v", err)
		return WriteResult{HealthChanged: s.noteWrite("hook runs", err)}, err
	}
	return WriteResult{Changed: n > 0, HealthChanged: s.noteWrite("hook runs", nil)}, nil
}

// SessionHooks returns one summary per (hook event, script) for a session,
// most runs first.
func (s *Store) SessionHooks(sessionID string) (out []HookSummary, readErr error) {
	defer func() { s.noteRead("hook runs", readErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT
			CASE WHEN instr(hook, ':') > 0 THEN substr(hook, 1, instr(hook, ':') - 1) ELSE hook END AS ev,
			script, COUNT(*),
			SUM(status IN ('error', 'cancelled')), SUM(status IN ('deny', 'block')),
			SUM(chars), SUM(duration_ms), MAX(`+timestampOrderExpr("ts")+`)
		FROM hook_runs WHERE session_id = ?
		GROUP BY ev, script ORDER BY COUNT(*) DESC, ev, script`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out = []HookSummary{}
	for rows.Next() {
		var h HookSummary
		if err := rows.Scan(&h.Event, &h.Script, &h.Runs, &h.Errors, &h.Blocks, &h.Chars, &h.TotalMs, &h.LastAt); err != nil {
			return nil, fmt.Errorf("scan hook summary: %w", err)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// pruneHookRunsLocked applies event time retention, then the row budget.
func (s *Store) pruneHookRunsLocked(before time.Time) {
	_, _ = s.db.Exec(`DELETE FROM hook_runs WHERE `+instantBeforeSQL("ts"), instantBound(before)...)
	_, _ = s.db.Exec(`DELETE FROM hook_runs WHERE id <
		(SELECT id FROM hook_runs ORDER BY id DESC LIMIT 1 OFFSET ?)`, hookRunBudget-1)
}
