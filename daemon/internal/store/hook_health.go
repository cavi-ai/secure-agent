package store

import (
	"fmt"
	"sort"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
	"github.com/cavi-ai/secure-agent/daemon/internal/hookhealth"
)

// SessionHookHealth examines at most the latest RunLimit completions in a
// fixed recent window. It never loads output text or infers a missing hook.
func (s *Store) SessionHookHealth(sessionID string, now time.Time) (out hookhealth.Assessment, readErr error) {
	defer func() { s.noteRead("hook health", readErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	runs, truncated, err := s.hookHealthRunsLocked("session_id=?", []any{sessionID}, now)
	if err != nil {
		return out, err
	}
	return hookhealth.Assess(runs, now, truncated), nil
}

type SessionHookFinding struct {
	SessionID string
	Finding   hookhealth.Finding
}

// ActiveHookFindings is a single bounded read across durable live sessions.
// Ended and unattributed sessions cannot acquire live attention items.
func (s *Store) ActiveHookFindings(now time.Time) (out []SessionHookFinding, truncated bool, readErr error) {
	defer func() { s.noteRead("hook health", readErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	runs, truncated, err := s.hookHealthRunsLocked("session_id IN (SELECT id FROM sessions WHERE status IN ('active','idle'))", nil, now)
	if err != nil {
		return nil, false, err
	}
	bySession := map[string][]hookrun.Record{}
	for _, r := range runs {
		bySession[r.SessionID] = append(bySession[r.SessionID], r)
	}
	for id, rs := range bySession {
		for _, f := range hookhealth.Assess(rs, now, truncated).Findings {
			if f.NeedsAction {
				out = append(out, SessionHookFinding{SessionID: id, Finding: f})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Finding.ID < out[j].Finding.ID })
	if len(out) > hookhealth.FindingLimit {
		out = out[:hookhealth.FindingLimit]
		truncated = true
	}
	return out, truncated, nil
}

func (s *Store) hookHealthRunsLocked(filter string, args []any, now time.Time) ([]hookrun.Record, bool, error) {
	args = append(args, now.Add(-hookhealth.Window).UTC().Format("2006-01-02T15:04:05.000000000Z"), now.UTC().Format("2006-01-02T15:04:05.000000000Z"), hookhealth.RunLimit+1)
	rows, err := s.db.Query(`SELECT run_id,ts,hook,script,status,duration_ms,chars,harness,evidence_json,session_id FROM hook_runs
		WHERE `+filter+` AND `+timestampOrderExpr("ts")+`>=? AND `+timestampOrderExpr("ts")+`<=?
		ORDER BY `+timestampOrderExpr("ts")+` DESC,run_id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var runs []hookrun.Record
	for rows.Next() {
		var r hookrun.Record
		var ts, metadata string
		if err := rows.Scan(&r.ID, &ts, &r.Event, &r.Script, &r.Status, &r.DurationMs, &r.Chars, &r.Harness, &metadata, &r.SessionID); err != nil {
			return nil, false, err
		}
		r.TS, err = time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return nil, false, fmt.Errorf("invalid persisted hook timestamp: %w", err)
		}
		r.Evidence, err = decodeHookEvidence(metadata)
		if err != nil {
			return nil, false, fmt.Errorf("invalid persisted hook metadata: %w", err)
		}
		runs = append(runs, r)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	truncated := len(runs) > hookhealth.RunLimit
	if truncated {
		// A coarse timestamp can tie many runs. Never omit a tied success
		// and then call the remaining errors consecutive.
		boundary := runs[hookhealth.RunLimit].TS
		runs = runs[:hookhealth.RunLimit]
		for len(runs) > 0 && runs[len(runs)-1].TS.Equal(boundary) {
			runs = runs[:len(runs)-1]
		}
	}
	return runs, truncated, nil
}
