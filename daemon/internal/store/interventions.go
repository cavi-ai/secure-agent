package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

const interventionsSchema = `CREATE TABLE IF NOT EXISTS interventions (
 id TEXT PRIMARY KEY, session_id TEXT NOT NULL DEFAULT '', session_key TEXT NOT NULL,
 requested_at TEXT NOT NULL, revision INTEGER NOT NULL, receipt_json TEXT NOT NULL
);`

// ReserveIntervention atomically claims an operation before any process call.
// A duplicate never grants authority to replay, even after restart.
func (s *Store) ReserveIntervention(r model.InterventionReceipt) (_ bool, writeErr error) {
	defer func() { s.noteWrite("intervention receipts", writeErr) }()
	if r.ID == "" || r.Revision != 1 || r.Status != "requested" {
		return false, fmt.Errorf("invalid intervention intent")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	r.SessionID = s.sessionIDForRootLocked(r.RootPID, r.RootStartedAt)
	raw, err := json.Marshal(r)
	if err != nil {
		return false, err
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO interventions(id,session_id,session_key,requested_at,revision,receipt_json) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`, r.ID, r.SessionID, r.SessionKey, r.RequestedAt.UTC().Format(time.RFC3339Nano), r.Revision, string(raw))
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

func (s *Store) SaveIntervention(r model.InterventionReceipt) (writeErr error) {
	defer func() { s.noteWrite("intervention receipts", writeErr) }()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	// Exact root identity, under the same lock as session rekeying.
	r.SessionID = s.sessionIDForRootLocked(r.RootPID, r.RootStartedAt)
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE interventions SET session_id=?,revision=?,receipt_json=? WHERE id=? AND revision<?`, r.SessionID, r.Revision, string(raw), r.ID, r.Revision)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("intervention intent missing or result stale")
	}
	// Bound completed history without dropping an in-flight intent.
	_, err = s.db.ExecContext(ctx, `DELETE FROM interventions WHERE json_extract(receipt_json,'$.status')!='requested' AND id NOT IN (SELECT id FROM interventions ORDER BY requested_at DESC,id DESC LIMIT 200)`)
	return err
}

func (s *Store) RecentInterventions(sessionID string, limit int) (_ []model.InterventionReceipt, readErr error) {
	defer func() { s.noteRead("intervention receipts", readErr) }()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	query := `SELECT id,session_id,session_key,requested_at,revision,receipt_json FROM interventions`
	args := []any{}
	if sessionID != "" {
		query += ` WHERE session_id=?`
		args = append(args, sessionID)
	}
	query += ` ORDER BY requested_at DESC,id DESC LIMIT ?`
	args = append(args, min(normalizeLimit(limit), 200))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.InterventionReceipt{}
	for rows.Next() {
		var id, storedSessionID, sessionKey, requestedAt, raw string
		var revision int64
		if err := rows.Scan(&id, &storedSessionID, &sessionKey, &requestedAt, &revision, &raw); err != nil {
			return nil, err
		}
		var r *model.InterventionReceipt
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			return nil, err
		}
		if r == nil || r.ID == "" || r.ID != id || r.SessionID != storedSessionID || r.SessionKey != sessionKey || r.Revision < 1 || r.Revision != revision {
			return nil, fmt.Errorf("invalid intervention receipt identity")
		}
		indexedAt, err := time.Parse(time.RFC3339Nano, requestedAt)
		if err != nil || !indexedAt.Equal(r.RequestedAt) {
			return nil, fmt.Errorf("invalid intervention receipt timestamp")
		}
		out = append(out, *r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return out, nil
}
