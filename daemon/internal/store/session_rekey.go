package store

import (
	"fmt"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// RekeySession moves every durable session reference in one transaction.
// Replayed calls merge by identity, preserving terminal state and peak usage.
// Any statement or commit failure leaves the old identity available for retry.
func (s *Store) RekeySession(oldID, newID string) error {
	return s.rekeySession(oldID, newID, nil)
}

// PromoteSession persists a deferred process-tree session and rekeys its
// evidence atomically, before the resolver publishes its canonical identity.
func (s *Store) PromoteSession(provisional model.Session, newID string) error {
	return s.rekeySession(provisional.ID, newID, &provisional)
}

func (s *Store) rekeySession(oldID, newID string, provisional *model.Session) (err error) {
	if oldID == "" || newID == "" || oldID == newID {
		return nil
	}
	s.egressMu.Lock()
	defer s.egressMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	defer func() {
		if err != nil || changed {
			s.noteWrite("session rekeys", err)
		}
	}()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	exec := func(q string, args ...any) error {
		res, err := tx.Exec(q, args...)
		if err != nil {
			return fmt.Errorf("rekey session: %w", err)
		}
		n, err := res.RowsAffected()
		if n > 0 {
			changed = true
		}
		return err
	}
	if provisional != nil {
		p := *provisional
		var endedAt any
		if p.EndedAt != nil {
			endedAt = p.EndedAt.UTC().Format(time.RFC3339Nano)
		}
		if err := exec(`INSERT INTO sessions (id,harness,workspace,repo,branch,root_pid,root_started_at,parent_id,started_at,ended_at,last_seen_at,status,confidence,origin)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`, oldID, p.Harness, p.Workspace, p.Repo, p.Branch, p.RootPID, p.RootStartedAt, p.ParentID, p.StartedAt.UTC().Format(time.RFC3339Nano), endedAt, p.LastSeenAt.UTC().Format(time.RFC3339Nano), p.Status, p.Confidence, p.Origin); err != nil {
			return err
		}
	}
	var conflicts int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM events o JOIN events n ON n.session_id=? AND n.call_id=o.call_id WHERE o.session_id=? AND n.kind!=o.kind`, newID, oldID).Scan(&conflicts); err != nil {
		return err
	}
	if conflicts > 0 {
		return fmt.Errorf("rekey session: call identity spans different event kinds")
	}
	// Prefer an already canonical terminal result. Otherwise promote the
	// provisional completion; starts never overwrite completions.
	if err := exec(`UPDATE events AS n SET
		model=COALESCE(NULLIF(n.model,''),(SELECT o.model FROM events o WHERE o.session_id=? AND o.call_id=n.call_id)),
		provider=COALESCE(NULLIF(n.provider,''),(SELECT o.provider FROM events o WHERE o.session_id=? AND o.call_id=n.call_id)),
		tool_status=CASE WHEN COALESCE(n.tool_status,'') IN ('','running') THEN COALESCE((SELECT o.tool_status FROM events o WHERE o.session_id=? AND o.call_id=n.call_id),n.tool_status) ELSE n.tool_status END,
		duration_ms=MAX(COALESCE(n.duration_ms,0),COALESCE((SELECT o.duration_ms FROM events o WHERE o.session_id=? AND o.call_id=n.call_id),0)),
		tokens_in=MAX(COALESCE(n.tokens_in,0),COALESCE((SELECT o.tokens_in FROM events o WHERE o.session_id=? AND o.call_id=n.call_id),0)),
		tokens_out=MAX(COALESCE(n.tokens_out,0),COALESCE((SELECT o.tokens_out FROM events o WHERE o.session_id=? AND o.call_id=n.call_id),0)),
		cost_usd=MAX(COALESCE(n.cost_usd,0),COALESCE((SELECT o.cost_usd FROM events o WHERE o.session_id=? AND o.call_id=n.call_id),0)),
		record=MAX(n.record,COALESCE((SELECT o.record FROM events o WHERE o.session_id=? AND o.call_id=n.call_id),0))
		WHERE n.session_id=? AND n.call_id IN (SELECT call_id FROM events WHERE session_id=?)`, oldID, oldID, oldID, oldID, oldID, oldID, oldID, oldID, newID, oldID); err != nil {
		return err
	}
	if err := exec(`DELETE FROM events WHERE session_id=? AND call_id IN (SELECT call_id FROM events WHERE session_id=?)`, oldID, newID); err != nil {
		return err
	}
	// Turns retain their timestamp identity when provisional and canonical
	// collectors have both observed the same turn.
	if err := exec(`UPDATE events AS n SET record=MAX(record,COALESCE((SELECT MAX(o.record) FROM events o WHERE o.kind=13 AND o.session_id=? AND o.ts=n.ts),0)) WHERE n.kind=13 AND n.session_id=? AND n.ts IN (SELECT ts FROM events WHERE kind=13 AND session_id=?)`, oldID, newID, oldID); err != nil {
		return err
	}
	if err := exec(`DELETE FROM events WHERE kind=13 AND session_id=? AND ts IN (SELECT ts FROM events WHERE kind=13 AND session_id=?)`, oldID, newID); err != nil {
		return err
	}
	var target int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM sessions WHERE id=?`, newID).Scan(&target); err != nil {
		return err
	}
	if target > 0 {
		if err := exec(`UPDATE sessions SET
			parent_id=CASE WHEN COALESCE(parent_id,'')='' THEN COALESCE((SELECT parent_id FROM sessions WHERE id=? AND parent_id!=?), '') ELSE parent_id END,
			origin=CASE WHEN COALESCE(origin,'')='' THEN COALESCE((SELECT origin FROM sessions WHERE id=?),'') ELSE origin END
			WHERE id=? AND EXISTS(SELECT 1 FROM sessions WHERE id=?)`, oldID, newID, oldID, newID, oldID); err != nil {
			return err
		}
		if err := exec(`DELETE FROM sessions WHERE id=?`, oldID); err != nil {
			return err
		}
	} else if err := exec(`UPDATE sessions SET id=?,parent_id=CASE WHEN parent_id=? THEN '' ELSE parent_id END WHERE id=?`, newID, newID, oldID); err != nil {
		return err
	}
	for _, spec := range []struct {
		q    string
		args []any
	}{
		{`UPDATE sessions SET parent_id=CASE WHEN id=? THEN '' ELSE ? END WHERE parent_id=?`, []any{newID, newID, oldID}},
		{`UPDATE events SET session_id=? WHERE session_id=?`, []any{newID, oldID}},
		{`UPDATE flags SET session_id=? WHERE session_id=?`, []any{newID, oldID}},
		{`UPDATE guard_decisions SET session_id=? WHERE session_id=?`, []any{newID, oldID}},
		{`UPDATE resource_episodes SET session_id=?,episode_json=json_set(episode_json,'$.session_id',?) WHERE session_id=?`, []any{newID, newID, oldID}},
		{`UPDATE incidents SET session_id=?,report_json=json_set(report_json,'$.session_id',?) WHERE session_id=?`, []any{newID, newID, oldID}},
		{`UPDATE egress_episodes SET session_ids_json=(SELECT json_group_array(sid) FROM (SELECT CASE WHEN value=? THEN ? ELSE value END AS sid,MIN(CAST(key AS INTEGER)) AS pos FROM json_each(session_ids_json) GROUP BY sid ORDER BY pos)) WHERE EXISTS(SELECT 1 FROM json_each(session_ids_json) WHERE value=?)`, []any{oldID, newID, oldID}},
	} {
		if err := exec(spec.q, spec.args...); err != nil {
			return err
		}
	}
	if err := rekeyFindingReviewsTx(tx, oldID, newID); err != nil {
		return err
	}
	return tx.Commit()
}
