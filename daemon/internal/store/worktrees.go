package store

import (
	"database/sql"
	"log"
	"strings"
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

// cleanup_log is the ledger of tidying actions and the bytes each gave back.
const cleanupLogSchema = `CREATE TABLE IF NOT EXISTS cleanup_log (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ts TEXT NOT NULL,
	action TEXT NOT NULL,
	path TEXT NOT NULL,
	repo TEXT,
	bytes INTEGER NOT NULL DEFAULT 0,
	detail TEXT
);`

// maxCleanupLog bounds the ledger like the audit log: rows come from
// API-triggerable actions.
const maxCleanupLog = 20000

// PutCleanup appends a ledger row, stamped now when TS is zero.
func (s *Store) PutCleanup(e model.CleanupEntry) {
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec(`INSERT INTO cleanup_log (ts, action, path, repo, bytes, detail) VALUES (?, ?, ?, ?, ?, ?)`,
		e.TS.UTC().Format(time.RFC3339Nano), e.Action, e.Path, e.Repo, e.Bytes, e.Detail); err != nil {
		log.Printf("store: insert cleanup row: %v", err)
		return
	}
	_, _ = s.db.Exec(`DELETE FROM cleanup_log WHERE id NOT IN (SELECT id FROM cleanup_log ORDER BY id DESC LIMIT ?)`, maxCleanupLog)
}

// CleanupLog returns the newest ledger rows first.
func (s *Store) CleanupLog(limit int) []model.CleanupEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id, ts, action, path, COALESCE(repo, ''), bytes, COALESCE(detail, '') FROM cleanup_log ORDER BY id DESC LIMIT ?`, normalizeLimit(limit))
	if err != nil {
		log.Printf("store: query cleanup log: %v", err)
		return nil
	}
	defer rows.Close()
	out := []model.CleanupEntry{}
	for rows.Next() {
		var e model.CleanupEntry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Action, &e.Path, &e.Repo, &e.Bytes, &e.Detail); err != nil {
			continue
		}
		e.TS, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		log.Printf("store: cleanup log cursor error (result may be truncated): %v", err)
	}
	return out
}

// CleanupTotals sums the ledger over all time and the 30 days before now.
func (s *Store) CleanupTotals(now time.Time) model.CleanupTotals {
	s.mu.Lock()
	defer s.mu.Unlock()
	var t model.CleanupTotals
	cut := now.Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	err := s.db.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN trashed THEN 0 ELSE bytes END), 0), COALESCE(SUM(NOT trashed), 0),
		COALESCE(SUM(CASE WHEN ts >= ? AND NOT trashed THEN bytes ELSE 0 END), 0), COALESCE(SUM(ts >= ? AND NOT trashed), 0),
		COALESCE(SUM(CASE WHEN trashed THEN bytes ELSE 0 END), 0), COALESCE(SUM(trashed), 0)
		FROM (SELECT ts, bytes, action LIKE 'trash:%' AS trashed FROM cleanup_log)`, cut, cut).
		Scan(&t.Bytes, &t.Count, &t.Bytes30d, &t.Count30d, &t.TrashedBytes, &t.TrashedCount)
	if err != nil {
		log.Printf("store: cleanup totals: %v", err)
	}
	return t
}

// agent_asks records each request to a worktree's owning agent and what
// it answered.
const agentAsksSchema = `CREATE TABLE IF NOT EXISTS agent_asks (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ts TEXT NOT NULL,
	path TEXT NOT NULL,
	repo TEXT,
	harness TEXT NOT NULL,
	session_id TEXT NOT NULL,
	status TEXT NOT NULL,
	verdict TEXT,
	detail TEXT,
	cost_usd REAL,
	output TEXT,
	finished_at TEXT
);`

// maxAgentAsks bounds the table (rows come from API-triggered asks).
const maxAgentAsks = 5000

// PutAgentAsk inserts an ask and returns its id.
func (s *Store) PutAgentAsk(a model.AgentAsk) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`INSERT INTO agent_asks (ts, path, repo, harness, session_id, status, verdict, detail, cost_usd, output)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.TS.UTC().Format(time.RFC3339Nano), a.Path, a.Repo, a.Harness, a.SessionID, a.Status, a.Verdict, a.Detail, a.CostUSD, a.Output)
	if err != nil {
		log.Printf("store: insert agent ask: %v", err)
		return 0
	}
	_, _ = s.db.Exec(`DELETE FROM agent_asks WHERE id NOT IN (SELECT id FROM agent_asks ORDER BY id DESC LIMIT ?)`, maxAgentAsks)
	id, _ := res.LastInsertId()
	return id
}

// FinishAgentAsk records an ask's outcome.
func (s *Store) FinishAgentAsk(a model.AgentAsk) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fin := ""
	if a.FinishedAt != nil {
		fin = a.FinishedAt.UTC().Format(time.RFC3339Nano)
	}
	if _, err := s.db.Exec(`UPDATE agent_asks SET status = ?, verdict = ?, detail = ?, cost_usd = ?, output = ?, finished_at = ? WHERE id = ?`,
		a.Status, a.Verdict, a.Detail, a.CostUSD, a.Output, fin, a.ID); err != nil {
		log.Printf("store: finish agent ask: %v", err)
	}
}

// AgentAsks returns asks newest first.
func (s *Store) AgentAsks(limit int) []model.AgentAsk {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id, ts, path, COALESCE(repo, ''), harness, session_id, status, COALESCE(verdict, ''),
		COALESCE(detail, ''), COALESCE(cost_usd, 0), COALESCE(output, ''), COALESCE(finished_at, '')
		FROM agent_asks ORDER BY id DESC LIMIT ?`, normalizeLimit(limit))
	if err != nil {
		log.Printf("store: query agent asks: %v", err)
		return nil
	}
	defer rows.Close()
	out := []model.AgentAsk{}
	for rows.Next() {
		var a model.AgentAsk
		var ts, fin string
		if err := rows.Scan(&a.ID, &ts, &a.Path, &a.Repo, &a.Harness, &a.SessionID, &a.Status, &a.Verdict, &a.Detail, &a.CostUSD, &a.Output, &fin); err != nil {
			continue
		}
		a.TS, _ = time.Parse(time.RFC3339Nano, ts)
		if t, err := time.Parse(time.RFC3339Nano, fin); err == nil {
			a.FinishedAt = &t
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		log.Printf("store: agent asks cursor error (result may be truncated): %v", err)
	}
	return out
}

// SessionsInWorkspace returns hook- and transcript-identified sessions
// whose workspace is dir or under it, newest first: their ids are the
// harness's own, so they can be resumed.
func (s *Store) SessionsInWorkspace(dir string) []model.Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(sessionSelect+` WHERE (workspace = ? OR workspace LIKE ? ESCAPE '\') AND confidence IN (?, ?)
		ORDER BY last_seen_at DESC LIMIT 20`,
		dir, likePrefix(dir)+"/%", model.ConfHook, model.ConfTranscript)
	if err != nil {
		log.Printf("store: sessions in workspace: %v", err)
		return nil
	}
	return scanSessions(rows)
}

// likePrefix escapes LIKE wildcards in a literal path.
func likePrefix(p string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(p)
}
