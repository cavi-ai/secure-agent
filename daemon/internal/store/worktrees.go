package store

import (
	"database/sql"
	"log"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// worktree_repos is the worktree hunter's saved repository list: every repo
// a scan found (from agent sessions, well-known worktree directories or scan
// roots) plus the ones the operator added by hand.
const worktreeReposSchema = `CREATE TABLE IF NOT EXISTS worktree_repos (
	path TEXT PRIMARY KEY,
	source TEXT NOT NULL,
	first_seen TEXT NOT NULL,
	last_scan TEXT,
	hidden INTEGER NOT NULL DEFAULT 0
);`

// UpsertWorktreeRepo records a sighting of a repo. A new row takes source;
// an existing row keeps its source unless source is manual (an operator add
// is the strongest claim), and a manual add also unhides the repo. Other
// sightings never change hidden.
func (s *Store) UpsertWorktreeRepo(path, source string, at time.Time) {
	if path == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ts := at.UTC().Format(time.RFC3339Nano)
	_, err := s.db.Exec(`INSERT INTO worktree_repos (path, source, first_seen, last_scan, hidden)
		VALUES (?, ?, ?, ?, 0)
		ON CONFLICT(path) DO UPDATE SET
		last_scan = excluded.last_scan,
		source = CASE WHEN excluded.source = ? THEN excluded.source ELSE worktree_repos.source END,
		hidden = CASE WHEN excluded.source = ? THEN 0 ELSE worktree_repos.hidden END`,
		path, source, ts, ts, model.RepoSourceManual, model.RepoSourceManual)
	if err != nil {
		log.Printf("store: upsert worktree repo: %v", err)
	}
}

// SetWorktreeRepoHidden hides or unhides a saved repo. Reports whether the
// repo was on the list.
func (s *Store) SetWorktreeRepoHidden(path string, hidden bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`UPDATE worktree_repos SET hidden = ? WHERE path = ?`, hidden, path)
	if err != nil {
		log.Printf("store: hide worktree repo: %v", err)
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

// WorktreeRepos returns the saved list ordered by path, hidden rows included.
func (s *Store) WorktreeRepos() []model.WorktreeRepo {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT path, source, first_seen, COALESCE(last_scan, ''), hidden FROM worktree_repos ORDER BY path`)
	if err != nil {
		log.Printf("store: query worktree repos: %v", err)
		return nil
	}
	defer rows.Close()
	out := []model.WorktreeRepo{}
	for rows.Next() {
		var r model.WorktreeRepo
		var first, last string
		if err := rows.Scan(&r.Path, &r.Source, &first, &last, &r.Hidden); err != nil {
			continue
		}
		r.FirstSeen, _ = time.Parse(time.RFC3339Nano, first)
		r.LastScan, _ = time.Parse(time.RFC3339Nano, last)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		log.Printf("store: worktree repos cursor error (result may be truncated): %v", err)
	}
	return out
}

// WorkspaceActivity returns one row per absolute session workspace: the
// newest last_seen across its sessions and whether any of them is still
// active or idle (not ended).
func (s *Store) WorkspaceActivity() []model.WorkspaceActivity {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT workspace, MAX(last_seen_at), MAX(status IN (?, ?))
		FROM sessions WHERE workspace LIKE '/%' GROUP BY workspace`,
		model.SessionActive, model.SessionIdle)
	if err != nil {
		log.Printf("store: query workspace activity: %v", err)
		return nil
	}
	defer rows.Close()
	out := []model.WorkspaceActivity{}
	for rows.Next() {
		var a model.WorkspaceActivity
		var last sql.NullString
		if err := rows.Scan(&a.Workspace, &last, &a.Live); err != nil {
			continue
		}
		a.LastSeen, _ = time.Parse(time.RFC3339Nano, last.String)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		log.Printf("store: workspace activity cursor error (result may be truncated): %v", err)
	}
	return out
}
