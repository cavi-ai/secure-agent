package store

import (
	"database/sql"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// sessions is the durable spine: one row per harness session, surviving
// process exit. Attribution happens at ingest (the resolver); this file is
// just the persistence.

const sessionsSchema = `CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,
	harness TEXT,
	workspace TEXT,
	repo TEXT,
	branch TEXT,
	root_pid INTEGER,
	root_started_at TEXT,
	parent_id TEXT,
	started_at TEXT,
	ended_at TEXT,
	last_seen_at TEXT,
	status TEXT,
	confidence TEXT
);`

// UpsertSession inserts or refreshes a session. Metadata fields are filled
// only when the incoming value is non-empty (a process-tree re-resolve never
// erases hook-provided repo/branch), and confidence never downgrades.
func (s *Store) UpsertSession(sess model.Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upsertSessionLocked(sess)
}

func (s *Store) upsertSessionLocked(sess model.Session) {
	if sess.ID == "" {
		return
	}
	var cur struct {
		workspace, repo, branch, status, confidence string
	}
	err := s.db.QueryRow(`SELECT workspace, repo, branch, status, confidence FROM sessions WHERE id = ?`, sess.ID).
		Scan(&cur.workspace, &cur.repo, &cur.branch, &cur.status, &cur.confidence)
	exists := err == nil
	if err != nil && err != sql.ErrNoRows {
		return
	}

	if exists {
		if sess.Workspace == "" {
			sess.Workspace = cur.workspace
		}
		if sess.Repo == "" {
			sess.Repo = cur.repo
		}
		if sess.Branch == "" {
			sess.Branch = cur.branch
		}
		if sess.Status == "" {
			sess.Status = cur.status
		}
		// Never reopen an ended session from a stale resolver pass; never
		// downgrade confidence (hook > transcript > process-tree).
		if cur.status == model.SessionEnded {
			sess.Status = model.SessionEnded
			sess.EndedAt = nil // keep stored ended_at via query below
		}
		if !model.StrongerConfidence(sess.Confidence, cur.confidence) {
			sess.Confidence = cur.confidence
		}
	}
	if sess.Status == "" {
		sess.Status = model.SessionActive
	}

	_, _ = s.db.Exec(`INSERT INTO sessions
		(id, harness, workspace, repo, branch, root_pid, root_started_at, parent_id, started_at, ended_at, last_seen_at, status, confidence)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
		harness = excluded.harness,
		workspace = excluded.workspace,
		repo = excluded.repo,
		branch = excluded.branch,
		root_pid = CASE WHEN excluded.root_pid != 0 THEN excluded.root_pid ELSE sessions.root_pid END,
		root_started_at = CASE WHEN excluded.root_started_at != '' THEN excluded.root_started_at ELSE sessions.root_started_at END,
		last_seen_at = excluded.last_seen_at,
		status = excluded.status,
		confidence = excluded.confidence`,
		sess.ID, sess.Harness, sess.Workspace, sess.Repo, sess.Branch,
		sess.RootPID, sess.RootStartedAt, sess.ParentID,
		sess.StartedAt.UTC().Format(time.RFC3339Nano), nil,
		sess.LastSeenAt.UTC().Format(time.RFC3339Nano), sess.Status, sess.Confidence)
}

// TouchSession bumps last_seen_at and reactivates an idle session. Ended
// sessions stay ended.
func (s *Store) TouchSession(id string, ts time.Time) {
	if id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.db.Exec(`UPDATE sessions SET last_seen_at = ?,
		status = CASE WHEN status = ? THEN ? ELSE status END
		WHERE id = ? AND status != ?`,
		ts.UTC().Format(time.RFC3339Nano),
		model.SessionIdle, model.SessionActive, id, model.SessionEnded)
}

// EndSession marks a session ended (root process gone, or explicit end).
func (s *Store) EndSession(id string, ts time.Time) {
	if id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t := ts.UTC().Format(time.RFC3339Nano)
	_, _ = s.db.Exec(`UPDATE sessions SET status = ?, ended_at = ?, last_seen_at = MAX(last_seen_at, ?) WHERE id = ? AND status != ?`,
		model.SessionEnded, t, t, id, model.SessionEnded)
}

// MarkSessionsIdle flips active sessions with no activity since cutoff to
// idle. Returns the ids flipped (the resolver ends their pid-less cousins).
func (s *Store) MarkSessionsIdle(cutoff time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := cutoff.UTC().Format(time.RFC3339Nano)
	rows, err := s.db.Query(`SELECT id FROM sessions WHERE status = ? AND last_seen_at < ?`, model.SessionActive, c)
	if err != nil {
		return nil
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	if len(ids) > 0 {
		_, _ = s.db.Exec(`UPDATE sessions SET status = ? WHERE status = ? AND last_seen_at < ?`, model.SessionIdle, model.SessionActive, c)
	}
	return ids
}

// LiveRootPIDs returns root pids of non-ended sessions so the resolver can
// end sessions whose process tree is gone.
func (s *Store) SessionRoots() map[int32]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT root_pid, id FROM sessions WHERE status != ? AND root_pid != 0`, model.SessionEnded)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := map[int32]string{}
	for rows.Next() {
		var pid int32
		var id string
		if rows.Scan(&pid, &id) == nil {
			out[pid] = id
		}
	}
	return out
}

// RekeySession renames a session id (hook id wins over the provisional
// process-tree id) and repoints its events and flags. One transaction: a
// crash mid-rekey must not strand half the attribution.
func (s *Store) RekeySession(oldID, newID string) {
	if oldID == "" || newID == "" || oldID == newID {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()
	// If the new id already exists, merge into it and drop the old row.
	var n int
	_ = tx.QueryRow(`SELECT COUNT(*) FROM sessions WHERE id = ?`, newID).Scan(&n)
	if n > 0 {
		_, _ = tx.Exec(`DELETE FROM sessions WHERE id = ?`, oldID)
	} else {
		_, _ = tx.Exec(`UPDATE sessions SET id = ? WHERE id = ?`, newID, oldID)
	}
	_, _ = tx.Exec(`UPDATE events SET session_id = ? WHERE session_id = ?`, newID, oldID)
	_, _ = tx.Exec(`UPDATE flags SET session_id = ? WHERE session_id = ?`, newID, oldID)
	_ = tx.Commit()
}

// SessionFilter narrows ListSessions. Status "" returns live (active+idle)
// plus ended up to Limit.
type SessionFilter struct {
	Status string // active | idle | ended | "" = all
	Limit  int    // 0 = 100
}

// ListSessions returns sessions ordered by last_seen_at DESC.
func (s *Store) ListSessions(f SessionFilter) []model.Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	query := `SELECT id, harness, workspace, repo, branch, root_pid, root_started_at, parent_id, started_at, ended_at, last_seen_at, status, confidence FROM sessions`
	args := []any{}
	if f.Status != "" {
		query += ` WHERE status = ?`
		args = append(args, f.Status)
	}
	query += ` ORDER BY last_seen_at DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []model.Session{}
	for rows.Next() {
		var sess model.Session
		var endedAt sql.NullString
		var startedAt, lastSeen string
		if err := rows.Scan(&sess.ID, &sess.Harness, &sess.Workspace, &sess.Repo, &sess.Branch,
			&sess.RootPID, &sess.RootStartedAt, &sess.ParentID, &startedAt, &endedAt, &lastSeen,
			&sess.Status, &sess.Confidence); err != nil {
			continue
		}
		sess.StartedAt, _ = time.Parse(time.RFC3339Nano, startedAt)
		sess.LastSeenAt, _ = time.Parse(time.RFC3339Nano, lastSeen)
		if endedAt.Valid && endedAt.String != "" {
			if t, err := time.Parse(time.RFC3339Nano, endedAt.String); err == nil {
				sess.EndedAt = &t
			}
		}
		out = append(out, sess)
	}
	return out
}

// GetSession returns one session by id.
func (s *Store) GetSession(id string) (model.Session, bool) {
	got := s.ListSessions(SessionFilter{Limit: 1000})
	for _, sess := range got {
		if sess.ID == id {
			return sess, true
		}
	}
	return model.Session{}, false
}

// pruneSessionsLocked bounds the ended-session tail: ended rows older than
// the event retention window are pure noise.
func (s *Store) pruneSessionsLocked() {
	cutoff := time.Now().Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	_, _ = s.db.Exec(`DELETE FROM sessions WHERE status = ? AND ended_at < ?`, model.SessionEnded, cutoff)
}
