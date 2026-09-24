package store

import (
	"database/sql"
	"path/filepath"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
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
	confidence TEXT,
	origin TEXT
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
		harness, workspace, repo, branch, status, confidence string
	}
	err := s.db.QueryRow(`SELECT harness, workspace, repo, branch, status, confidence FROM sessions WHERE id = ?`, sess.ID).
		Scan(&cur.harness, &cur.workspace, &cur.repo, &cur.branch, &cur.status, &cur.confidence)
	exists := err == nil
	if err != nil && err != sql.ErrNoRows {
		return
	}

	if exists {
		// Fill-only merge: an upsert that carries less identity than the row
		// must never erase it. Trace events (Tier 1) resolve WITHOUT a pid, so
		// they arrive harness-less; clobbering here is what stripped the
		// harness off every transcript-joined session and left the join
		// looking broken.
		if sess.Harness == "" {
			sess.Harness = cur.harness
		}
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
		(id, harness, workspace, repo, branch, root_pid, root_started_at, parent_id, started_at, ended_at, last_seen_at, status, confidence, origin)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
		harness = excluded.harness,
		workspace = excluded.workspace,
		repo = excluded.repo,
		branch = excluded.branch,
		root_pid = CASE WHEN excluded.root_pid != 0 THEN excluded.root_pid ELSE sessions.root_pid END,
		root_started_at = CASE WHEN excluded.root_started_at != '' THEN excluded.root_started_at ELSE sessions.root_started_at END,
		parent_id = CASE WHEN COALESCE(excluded.parent_id, '') != '' THEN excluded.parent_id ELSE sessions.parent_id END,
		last_seen_at = excluded.last_seen_at,
		status = excluded.status,
		confidence = excluded.confidence,
		origin = CASE WHEN COALESCE(excluded.origin, '') != '' THEN excluded.origin ELSE sessions.origin END`,
		sess.ID, sess.Harness, sess.Workspace, sess.Repo, sess.Branch,
		sess.RootPID, sess.RootStartedAt, sess.ParentID,
		sess.StartedAt.UTC().Format(time.RFC3339Nano), nil,
		sess.LastSeenAt.UTC().Format(time.RFC3339Nano), sess.Status, sess.Confidence, sess.Origin)
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
// Tool calls still marked "running" in that session are closed as "error":
// a session cannot finish while a call is in flight, and rows stuck at
// running poison pairing stats.
func (s *Store) EndSession(id string, ts time.Time) {
	if id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t := ts.UTC().Format(time.RFC3339Nano)
	_, _ = s.db.Exec(`UPDATE sessions SET status = ?, ended_at = ?, last_seen_at = MAX(last_seen_at, ?) WHERE id = ? AND status != ?`,
		model.SessionEnded, t, t, id, model.SessionEnded)
	_, _ = s.db.Exec(`UPDATE events SET tool_status = 'error'
		WHERE session_id = ? AND kind = ? AND tool_status = 'running'`,
		id, int(event.KindToolCall))
}

// SweepStaleRunningCalls closes tool-call rows stuck at "running" past the
// cutoff. EndSession sweeps its own session, but rows written before that
// sweep existed (or whose completion line was lost) stay running forever; a
// call cannot legitimately be in flight for hours. If the completion arrives
// late, the upsert on session_id+call_id flips the row back to ok.
func (s *Store) SweepStaleRunningCalls(cutoff time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`UPDATE events SET tool_status = 'error'
		WHERE kind = ? AND tool_status = 'running' AND ts < ?`,
		int(event.KindToolCall), cutoff.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	return int(n)
}

// RepairSessionGitIdentity rewrites repo/branch for rows whose stored repo
// carries the old basename heuristic's signature (repo equals the workspace
// basename, or repo is empty) when the resolver's current answer differs.
// Rows whose repo names something other than the workspace tail — a real
// handshake or walk-up resolution — are untouched. Confidence is no proof of
// origin here: fill-merge keeps a heuristic repo when a later handshake
// arrives with an empty one. Returns the number of repaired rows.
func (s *Store) RepairSessionGitIdentity(resolve func(workspace string) (repo, branch string)) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id, workspace, repo, branch FROM sessions
		WHERE workspace != '' LIMIT 5000`)
	if err != nil {
		return 0
	}
	type row struct{ id, ws, repo, branch string }
	var todo []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.ws, &r.repo, &r.branch); err == nil {
			todo = append(todo, r)
		}
	}
	rows.Close()
	repaired := 0
	for _, r := range todo {
		base := filepath.Base(filepath.Clean(r.ws))
		if r.repo != "" && r.repo != base {
			continue // a real resolution, not the basename heuristic
		}
		repo, branch := resolve(r.ws)
		if repo == r.repo && branch == r.branch {
			continue
		}
		if _, err := s.db.Exec(`UPDATE sessions SET repo = ?, branch = ? WHERE id = ?`, repo, branch, r.id); err == nil {
			repaired++
		}
	}
	return repaired
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

// SessionRoots returns root pids of non-ended sessions so the resolver can
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

// SessionsByRootPID returns the non-ended session for each live root pid,
// keyed by pid. The console/menubar join process trees to durable session
// identity with this (harness, workspace, repo, branch) so a tree row reads
// "claude · secure-agent@main" rather than a bare process cwd ("/").
func (s *Store) SessionsByRootPID() map[int32]model.Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id, harness, workspace, repo, branch, root_pid, root_started_at, parent_id, started_at, ended_at, last_seen_at, status, confidence, COALESCE(origin, '')
		FROM sessions WHERE status != ? AND root_pid != 0`, model.SessionEnded)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := map[int32]model.Session{}
	for rows.Next() {
		var sess model.Session
		var endedAt sql.NullString
		var startedAt, lastSeen string
		if err := rows.Scan(&sess.ID, &sess.Harness, &sess.Workspace, &sess.Repo, &sess.Branch,
			&sess.RootPID, &sess.RootStartedAt, &sess.ParentID, &startedAt, &endedAt, &lastSeen,
			&sess.Status, &sess.Confidence, &sess.Origin); err != nil {
			continue
		}
		out[sess.RootPID] = sess
	}
	return out
}

// RekeySession renames a session id (hook id wins over the provisional
// process-tree id) and repoints its events, flags and child sessions; the
// session keeps its own parent. One transaction: a
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
		// The merged row keeps the old row's parent and origin when it has none.
		_, _ = tx.Exec(`UPDATE sessions SET parent_id = COALESCE((SELECT parent_id FROM sessions WHERE id = ?), '')
			WHERE id = ? AND COALESCE(parent_id, '') = ''`, oldID, newID)
		_, _ = tx.Exec(`UPDATE sessions SET origin = COALESCE((SELECT origin FROM sessions WHERE id = ?), '')
			WHERE id = ? AND COALESCE(origin, '') = ''`, oldID, newID)
		_, _ = tx.Exec(`DELETE FROM sessions WHERE id = ?`, oldID)
	} else {
		_, _ = tx.Exec(`UPDATE sessions SET id = ? WHERE id = ?`, newID, oldID)
	}
	// Children of the old id follow it to the new one.
	_, _ = tx.Exec(`UPDATE sessions SET parent_id = ? WHERE parent_id = ? AND id != ?`, newID, oldID, newID)
	_, _ = tx.Exec(`UPDATE events SET session_id = ? WHERE session_id = ?`, newID, oldID)
	_, _ = tx.Exec(`UPDATE flags SET session_id = ? WHERE session_id = ?`, newID, oldID)
	_ = tx.Commit()
}

// SessionFilter narrows ListSessions. Status "" returns the DEFAULT view:
// live sessions (active+idle) first, then a bounded recent-ended tail —
// not a wall of ended stubs. Harness, Repo, Branch and Since narrow either
// view; every set field must match.
type SessionFilter struct {
	Status  string    // active | idle | ended | "" = live + recent ended
	Harness string    // exact match; "" = any
	Repo    string    // exact match; "" = any
	Branch  string    // exact match; "" = any
	Since   time.Time // started_at or last_seen_at at or after this; zero = any
	Limit   int       // 0 = 100
}

// where renders the Harness/Repo/Branch/Since clauses as " AND …" terms.
func (f SessionFilter) where() (string, []any) {
	var clause strings.Builder
	var args []any
	for _, c := range []struct{ col, val string }{{"harness", f.Harness}, {"repo", f.Repo}, {"branch", f.Branch}} {
		if c.val != "" {
			clause.WriteString(" AND " + c.col + " = ?")
			args = append(args, c.val)
		}
	}
	if !f.Since.IsZero() {
		since := f.Since.UTC().Format(time.RFC3339Nano)
		clause.WriteString(" AND (datetime(started_at) >= datetime(?) OR datetime(last_seen_at) >= datetime(?))")
		args = append(args, since, since)
	}
	return clause.String(), args
}

// defaultEndedTail caps how many ended sessions the default view carries.
const defaultEndedTail = 25

const sessionSelect = `SELECT id, harness, workspace, repo, branch, root_pid, root_started_at, parent_id, started_at, ended_at, last_seen_at, status, confidence, COALESCE(origin, '') FROM sessions`

// scanSessions reads sessionSelect rows and closes them.
func scanSessions(rows *sql.Rows) []model.Session {
	defer rows.Close()
	out := []model.Session{}
	for rows.Next() {
		var sess model.Session
		var endedAt sql.NullString
		var startedAt, lastSeen string
		if err := rows.Scan(&sess.ID, &sess.Harness, &sess.Workspace, &sess.Repo, &sess.Branch,
			&sess.RootPID, &sess.RootStartedAt, &sess.ParentID, &startedAt, &endedAt, &lastSeen,
			&sess.Status, &sess.Confidence, &sess.Origin); err != nil {
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

// ListSessions returns sessions. The default (Status "") ordering: live
// sessions by last_seen DESC, then the most recent ended ones, with the
// whole result capped at Limit. ?status=ended still fetches the ended
// population alone (the console's collapsible section paginates there).
func (s *Store) ListSessions(f SessionFilter) []model.Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	extra, extraArgs := f.where()
	query := func(statusClause string, statusArgs []any, n int) (*sql.Rows, error) {
		args := append(append(statusArgs, extraArgs...), n)
		return s.db.Query(sessionSelect+` WHERE `+statusClause+extra+` ORDER BY last_seen_at DESC LIMIT ?`, args...)
	}
	switch f.Status {
	case "":
		// Default view: live first, then the recent ended tail.
		rows, err := query(`status IN (?, ?)`, []any{model.SessionActive, model.SessionIdle}, limit)
		if err != nil {
			return nil
		}
		out := scanSessions(rows)
		if len(out) >= limit {
			return out
		}
		endedRows, err := query(`status = ?`, []any{model.SessionEnded}, min(defaultEndedTail, limit-len(out)))
		if err != nil {
			return out
		}
		return append(out, scanSessions(endedRows)...)
	default:
		rows, err := query(`status = ?`, []any{f.Status}, limit)
		if err != nil {
			return nil
		}
		return scanSessions(rows)
	}
}

// sessionByID reads one session row directly, whatever its status or age.
func (s *Store) sessionByID(id string) (model.Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(sessionSelect+` WHERE id = ?`, id)
	if err != nil {
		return model.Session{}, false
	}
	got := scanSessions(rows)
	if len(got) == 0 {
		return model.Session{}, false
	}
	return got[0], true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetSession returns one session by id, whatever its status or age.
func (s *Store) GetSession(id string) (model.Session, bool) {
	return s.sessionByID(id)
}

// pruneSessionsLocked bounds the ended-session tail: ended rows older than
// the event retention window are pure noise.
func (s *Store) pruneSessionsLocked() {
	cutoff := time.Now().Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	_, _ = s.db.Exec(`DELETE FROM sessions WHERE status = ? AND ended_at < ?`, model.SessionEnded, cutoff)
}
