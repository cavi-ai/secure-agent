package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
)

// Retention caps for the API-populated tables, so an always-on daemon's DB stays
// bounded. Events are pruned separately (batched) under per-kind row budgets
// (kindBudgets).
const (
	maxIncidents        = 5000  // one full report_json per flag
	maxAudit            = 50000 // long-lived security log, but still bounded against abuse
	maxFlags            = 10000 // flags are insert-only like events; cap them too
	maxResourceEpisodes = 500   // bounded full-family pressure snapshots
	episodeSettleWindow = 30 * time.Second
)

// jsonlRotateBytes caps the forensic flag mirror. SQLite is the source of
// truth and already prunes; JSONL is append-only unless rotated.
var jsonlRotateBytes int64 = 8 << 20

type Store struct {
	mu          sync.Mutex
	db          *sql.DB
	jsonlPath   string
	jsonlFile   *os.File
	insertCount uint64
	// Per-kind time-based retention. Socket churn (conn open/close) ages out
	// in hours; security-relevant kinds keep days. Count-based pruning stays
	// as a backstop — a busy machine must never let conn noise evict the
	// security record.
	connRetention  time.Duration
	eventRetention time.Duration
	// lastSeen[pid] = RFC3339Nano ts of the most recent event for that pid,
	// maintained on insert so the /status agents join is O(pids) map lookups
	// instead of a MAX(ts) GROUP BY scan over the events table (measured
	// 2–4s at ~400 live pids — past the UI's 3s socket timeout).
	lastSeen map[int32]string
}

// Retention defaults; both overrideable via config (retention.conn_event_hours,
// retention.event_days).
const (
	DefaultConnEventRetention = 24 * time.Hour
	DefaultEventRetention     = 7 * 24 * time.Hour
)

// SetEventRetention configures per-kind time-based pruning. Zero values fall
// back to the defaults.
func (s *Store) SetEventRetention(conn, other time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if conn <= 0 {
		conn = DefaultConnEventRetention
	}
	if other <= 0 {
		other = DefaultEventRetention
	}
	s.connRetention = conn
	s.eventRetention = other
}

// AuditEntry is one durable record of a policy/control change (a rule promoted
// or demoted, fingerprints ingested or reloaded). Unlike events, audit rows are
// low-volume and never pruned. No field ever carries a secret value.
type AuditEntry struct {
	ID       int64  `json:"id"`
	TS       string `json:"ts"`
	Action   string `json:"action"` // "rule-mode" | "fingerprint-ingest" | "fingerprint-reload"
	Rule     string `json:"rule,omitempty"`
	FromMode string `json:"from_mode,omitempty"`
	ToMode   string `json:"to_mode,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

func Open(dbPath, jsonlPath string) (*Store, error) {
	// State dirs are user-private: the db carries agent activity, evidence
	// chains, and guard decisions — nothing here needs group/other access.
	if dbPath != "" {
		if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
			return nil, fmt.Errorf("failed to create db dir: %w", err)
		}
	}
	if jsonlPath != "" {
		if err := os.MkdirAll(filepath.Dir(jsonlPath), 0o700); err != nil {
			return nil, fmt.Errorf("failed to create jsonl dir: %w", err)
		}
	}

	dsn := dbPath
	if dsn != "" {
		dsn = dsn + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(3000)"
	} else {
		dsn = ":memory:?_pragma=journal_mode(WAL)"
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite: %w", err)
	}

	createQueries := []string{
		`CREATE TABLE IF NOT EXISTS flags (
			id TEXT PRIMARY KEY,
			rule TEXT,
			severity INT,
			ts TEXT,
			pid INT,
			agent TEXT,
			session_id TEXT,
			workspace TEXT,
			evidence TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			kind INT,
			ts TEXT,
			pid INT,
			exe_path TEXT,
			session_id TEXT,
			path TEXT,
			remote_host TEXT,
			remote_port INT,
			detail TEXT,
			tool TEXT,
			tool_status TEXT,
			duration_ms INTEGER,
			model TEXT,
			tokens_in INTEGER,
			tokens_out INTEGER,
			cost_usd REAL,
			call_id TEXT,
			provider TEXT
		);`,
		`CREATE INDEX IF NOT EXISTS idx_events_pid_ts ON events(pid, ts);`,
		`CREATE TABLE IF NOT EXISTS incidents (
			id TEXT PRIMARY KEY,
			flag_id TEXT,
			pid INT,
			risk TEXT,
			report_json TEXT,
			created_at TEXT,
			status TEXT DEFAULT 'open',
			acknowledged_at TEXT,
			resolved_at TEXT,
			resolution_note TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS audit (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ts TEXT,
			action TEXT,
			rule TEXT,
			from_mode TEXT,
			to_mode TEXT,
			detail TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS guard_rules (
			agent TEXT NOT NULL,
			rule_id TEXT NOT NULL,
			decision TEXT NOT NULL,
			source TEXT,
			created_at TEXT,
			PRIMARY KEY (agent, rule_id)
		);`,
		// Per-path guard exceptions: exact paths (and their descendants) one
		// agent+rule may always access, WITHOUT widening to the whole rule.
		// The Little-Snitch per-path model: trust the specific file, not the
		// class. PRIMARY KEY includes the path so revocation is exact.
		`CREATE TABLE IF NOT EXISTS guard_path_allows (
			agent TEXT NOT NULL,
			rule_id TEXT NOT NULL,
			path TEXT NOT NULL,
			created_at TEXT,
			PRIMARY KEY (agent, rule_id, path)
		);`,
		// Hourly rollups: pre-aggregated counters so trend views (24h/7d
		// charts, advisor week-over-week context) are O(buckets), not
		// O(events). bucket is the UTC hour ("2006-01-02T15").
		`CREATE TABLE IF NOT EXISTS rollup_hourly (
			bucket TEXT NOT NULL,
			kind TEXT NOT NULL,
			count INT NOT NULL,
			PRIMARY KEY (bucket, kind)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_rollup_hourly_bucket ON rollup_hourly(bucket);`,
		// Local-advisor verdicts, keyed by the subject they annotate (a flag
		// id or an incident id). Advisory metadata only.
		`CREATE TABLE IF NOT EXISTS advisor_verdicts (
			subject_id TEXT PRIMARY KEY,
			kind TEXT,
			assessment TEXT,
			confidence REAL,
			rationale TEXT,
			suggested_action TEXT,
			model TEXT,
			created_at TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS resource_episodes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			captured_at TEXT NOT NULL,
			severity TEXT NOT NULL,
			session_key TEXT NOT NULL,
			episode_json TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_resource_episodes_captured_at ON resource_episodes(captured_at);`,
		sessionsSchema,
		`CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status, last_seen_at);`,
	}

	for _, q := range createQueries {
		if _, err := db.Exec(q); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to init db schema: %w", err)
		}
	}
	// Pre-session_id databases (CREATE TABLE IF NOT EXISTS is a no-op on them)
	// get the column added in place. Checked via PRAGMA so a fresh database
	// doesn't log a scary "duplicate column" error on every start.
	for _, table := range []string{"events", "flags"} {
		var n int
		if err := db.QueryRow(
			`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name='session_id'`, table,
		).Scan(&n); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to inspect %s schema: %w", table, err)
		}
		if n == 0 {
			if _, err := db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN session_id TEXT`); err != nil {
				db.Close()
				return nil, fmt.Errorf("failed to migrate %s.session_id: %w", table, err)
			}
			log.Printf("store: migrated %s: added session_id column", table)
		}
	}
	// flags.workspace (P5): the key for per-workspace notification scopes.
	var wsN int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('flags') WHERE name='workspace'`).Scan(&wsN); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to inspect flags.workspace: %w", err)
	}
	if wsN == 0 {
		if _, err := db.Exec(`ALTER TABLE flags ADD COLUMN workspace TEXT`); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to migrate flags.workspace: %w", err)
		}
		log.Printf("store: migrated flags: added workspace column")
	}
	// Trace columns (P2): older databases gain them in place.
	for _, col := range []string{"tool", "tool_status", "duration_ms", "model", "tokens_in", "tokens_out", "cost_usd", "call_id", "provider"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('events') WHERE name=?`, col).Scan(&n); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to inspect events schema: %w", err)
		}
		if n == 0 {
			typ := "TEXT"
			switch col {
			case "duration_ms", "tokens_in", "tokens_out":
				typ = "INTEGER"
			case "cost_usd":
				typ = "REAL"
			}
			if _, err := db.Exec(`ALTER TABLE events ADD COLUMN ` + col + ` ` + typ); err != nil {
				db.Close()
				return nil, fmt.Errorf("failed to migrate events.%s: %w", col, err)
			}
			log.Printf("store: migrated events: added %s column", col)
		}
	}
	// One row per harness tool call: a completion (same session+call_id)
	// upserts the start row instead of appending a second. A plain UNIQUE
	// index (not partial) so ON CONFLICT(session_id, call_id) resolves;
	// SQLite treats NULL call_ids as distinct, so non-tool events (NULL)
	// never collide.
	//
	// Created HERE, after the call_id migration above: on an older database
	// the index would otherwise reference a column that did not yet exist and
	// Open() would fail.
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_events_call ON events(session_id, call_id);`); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create events call index: %w", err)
	}
	// A partial idx_events_call from an earlier build does not satisfy
	// ON CONFLICT(session_id, call_id). Detect the stale, same-name partial
	// index and replace it (indexes aren't IF-NOT-EXISTS-replaceable).
	var idxSQL string
	if err := db.QueryRow(`SELECT COALESCE(sql,'') FROM sqlite_master WHERE type='index' AND name='idx_events_call'`).Scan(&idxSQL); err == nil {
		if strings.Contains(idxSQL, "WHERE") {
			if _, err := db.Exec(`DROP INDEX IF EXISTS idx_events_call`); err != nil {
				db.Close()
				return nil, fmt.Errorf("failed to drop stale call index: %w", err)
			}
			if _, err := db.Exec(`CREATE UNIQUE INDEX idx_events_call ON events(session_id, call_id);`); err != nil {
				db.Close()
				return nil, fmt.Errorf("failed to recreate events call index: %w", err)
			}
			log.Printf("store: replaced partial idx_events_call with a full unique index")
		}
	}
	// Dedupe turns and model calls on (session, ts): a transcript re-read
	// replays the same record with the same timestamp, and without a
	// constraint each replay double-counts the turn/call. Delete existing
	// duplicates first or the unique index fails to build.
	if _, err := db.Exec(`DELETE FROM events WHERE kind IN (13, 14) AND id NOT IN (
		SELECT MIN(id) FROM events WHERE kind IN (13, 14) GROUP BY kind, session_id, ts)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to dedupe turn/model-call events: %w", err)
	}
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_events_turn_dedupe ON events(kind, session_id, ts) WHERE kind IN (13, 14) AND session_id != '';`); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create turn dedupe index: %w", err)
	}
	// Flags gain an acknowledged marker: when the operator acts on a flag
	// (applies any disposition), the flag stops counting as critical and
	// dims in the UI — "acted upon" is a first-class state, not an endless
	// red row. Same PRAGMA-checked migration pattern as session_id.
	var ackN int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('flags') WHERE name='acknowledged'`,
	).Scan(&ackN); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to inspect flags schema: %w", err)
	}
	if ackN == 0 {
		if _, err := db.Exec(`ALTER TABLE flags ADD COLUMN acknowledged TEXT`); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to migrate flags.acknowledged: %w", err)
		}
		log.Printf("store: migrated flags: added acknowledged column")
	}
	// Incidents workflow columns: the acknowledge/resolve endpoints write
	// status/acknowledged_at/resolved_at/resolution_note. Without this
	// migration those writes fail with "no such column" and the dashboard's
	// Acknowledge/Resolve buttons are dead (the exact "dismiss doesn't
	// work" dogfood complaint).
	var wfN int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('incidents') WHERE name='status'`,
	).Scan(&wfN); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to inspect incidents schema: %w", err)
	}
	if wfN == 0 {
		for _, col := range []string{
			`ALTER TABLE incidents ADD COLUMN status TEXT`,
			`ALTER TABLE incidents ADD COLUMN acknowledged_at TEXT`,
			`ALTER TABLE incidents ADD COLUMN resolved_at TEXT`,
			`ALTER TABLE incidents ADD COLUMN resolution_note TEXT`,
		} {
			if _, err := db.Exec(col); err != nil {
				db.Close()
				return nil, fmt.Errorf("failed to migrate incidents workflow columns: %w", err)
			}
		}
		log.Printf("store: migrated incidents: added workflow columns (status, acknowledged_at, resolved_at, resolution_note)")
	}
	// Incident aggregation columns (P2): one incident per rule+session+subject;
	// flags become its evidence. Older rows keep NULLs and simply never match
	// an aggregation key — they stay standalone, which is what they were.
	var aggN int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('incidents') WHERE name='aggregate_count'`,
	).Scan(&aggN); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to inspect incidents schema: %w", err)
	}
	if aggN == 0 {
		for _, col := range []string{
			`ALTER TABLE incidents ADD COLUMN rule TEXT`,
			`ALTER TABLE incidents ADD COLUMN session_id TEXT`,
			`ALTER TABLE incidents ADD COLUMN subject TEXT`,
			`ALTER TABLE incidents ADD COLUMN aggregate_count INTEGER`,
			`ALTER TABLE incidents ADD COLUMN last_flag_at TEXT`,
			`ALTER TABLE incidents ADD COLUMN flag_ids TEXT`,
		} {
			if _, err := db.Exec(col); err != nil {
				db.Close()
				return nil, fmt.Errorf("failed to migrate incidents aggregation columns: %w", err)
			}
		}
		log.Printf("store: migrated incidents: added aggregation columns (rule, session_id, subject, aggregate_count, last_flag_at, flag_ids)")
	}

	var jsonl *os.File
	if jsonlPath != "" {
		f, err := os.OpenFile(jsonlPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			log.Printf("store: warning: failed to open jsonl path %s: %v", jsonlPath, err)
		} else {
			jsonl = f
		}
	}

	// SQLite honors the process umask for the db and its WAL/SHM sidecars; the
	// daemon may inherit a permissive umask from its launcher, so tighten the
	// resulting files explicitly.
	if dbPath != "" {
		for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
			if f, err := os.Stat(p); err == nil && f.Mode().Perm()&0o077 != 0 {
				if err := os.Chmod(p, 0o600); err != nil {
					log.Printf("store: warning: failed to tighten %s perms: %v", p, err)
				}
			}
		}
	}

	return &Store{
		db:        db,
		jsonlPath: jsonlPath,
		jsonlFile: jsonl,
	}, nil
}

func (s *Store) PutFlag(fl model.Flag) {
	s.mu.Lock()
	defer s.mu.Unlock()

	evJSON, _ := json.Marshal(fl.Evidence)
	tsStr := fl.TS.UTC().Format(time.RFC3339Nano)

	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO flags (id, rule, severity, ts, pid, agent, session_id, workspace, evidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		fl.ID, fl.Rule, fl.Severity, tsStr, fl.PID, fl.Agent, fl.SessionID, fl.Workspace, string(evJSON),
	)
	if err != nil {
		log.Printf("store: failed to insert flag %s: %v", fl.ID, err)
	} else {
		s.bumpRollupLocked(fmt.Sprintf("flag:s%d", fl.Severity), fl.TS)
	}

	// Retention: flags are insert-only like events and must be capped too, or
	// an always-on daemon on a noisy host grows the DB without limit.
	_, _ = s.db.Exec(`DELETE FROM flags WHERE rowid NOT IN (SELECT rowid FROM flags ORDER BY datetime(ts) DESC, ts DESC LIMIT ?)`, maxFlags)

	if s.jsonlFile != nil {
		s.maybeRotateJSONLLocked()
		if s.jsonlFile != nil {
			data, err := json.Marshal(fl)
			if err == nil {
				s.jsonlFile.Write(append(data, '\n'))
			}
		}
	}
}

func (s *Store) maybeRotateJSONLLocked() {
	if s.jsonlFile == nil || s.jsonlPath == "" || jsonlRotateBytes <= 0 {
		return
	}
	st, err := s.jsonlFile.Stat()
	if err != nil || st.Size() < jsonlRotateBytes {
		return
	}
	_ = s.jsonlFile.Close()
	s.jsonlFile = nil
	rotated := s.jsonlPath + ".1"
	_ = os.Remove(rotated)
	if err := os.Rename(s.jsonlPath, rotated); err != nil {
		log.Printf("store: warning: jsonl rotate rename failed: %v", err)
		return
	}
	f, err := os.OpenFile(s.jsonlPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		log.Printf("store: warning: jsonl rotate reopen failed: %v", err)
		return
	}
	s.jsonlFile = f
}

func (s *Store) PutEvent(e event.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tsStr := e.TS.UTC().Format(time.RFC3339Nano)
	// Tool calls are keyed by (session_id, call_id): the harness emits a start
	// (status "running") and later a completion for the SAME call, and a
	// transcript re-read can replay both. The upsert folds them into one row —
	// the start inserts, the completion updates status/duration in place.
	// Non-tool events (call_id NULL) never match the partial unique index and
	// always insert.
	var err error
	var res sql.Result
	if e.CallID != "" {
		res, err = s.db.Exec(
			`INSERT INTO events (kind, ts, pid, exe_path, session_id, path, remote_host, remote_port, detail, tool, tool_status, duration_ms, model, tokens_in, tokens_out, cost_usd, call_id)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(session_id, call_id) DO UPDATE SET
			   tool_status = CASE WHEN excluded.tool_status != '' AND excluded.tool_status != 'running' THEN excluded.tool_status ELSE events.tool_status END,
			   duration_ms = CASE WHEN excluded.duration_ms > 0 THEN excluded.duration_ms ELSE events.duration_ms END,
			   tokens_in   = CASE WHEN excluded.tokens_in  > 0 THEN excluded.tokens_in  ELSE events.tokens_in  END,
			   tokens_out  = CASE WHEN excluded.tokens_out > 0 THEN excluded.tokens_out ELSE events.tokens_out END,
			   cost_usd    = CASE WHEN excluded.cost_usd   > 0 THEN excluded.cost_usd   ELSE events.cost_usd   END`,
			int(e.Kind), tsStr, e.PID, e.ExePath, e.SessionID, e.Path, e.RemoteHost, e.RemotePort, e.Detail,
			nullStr(e.ToolName), nullStr(e.ToolStatus), nullInt(e.DurationMs), nullStr(e.Model), nullInt(e.TokensIn), nullInt(e.TokensOut), nullFloat(e.CostUSD), e.CallID,
		)
	} else {
		// Turns and model calls dedupe on (kind, session_id, ts) — a
		// transcript re-read replays the same record and must not
		// double-count. INSERT OR IGNORE relies on the partial unique index
		// created at open; other kinds always insert.
		verb := "INSERT"
		if e.Kind == event.KindTurn || e.Kind == event.KindModelCall {
			verb = "INSERT OR IGNORE"
		}
		res, err = s.db.Exec(
			verb+` INTO events (kind, ts, pid, exe_path, session_id, path, remote_host, remote_port, detail, tool, tool_status, duration_ms, model, tokens_in, tokens_out, cost_usd, provider)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			int(e.Kind), tsStr, e.PID, e.ExePath, e.SessionID, e.Path, e.RemoteHost, e.RemotePort, e.Detail,
			nullStr(e.ToolName), nullStr(e.ToolStatus), nullInt(e.DurationMs), nullStr(e.Model), nullInt(e.TokensIn), nullInt(e.TokensOut), nullFloat(e.CostUSD), nullStr(e.Provider),
		)
	}
	if err != nil {
		log.Printf("store: failed to insert event: %v", err)
	} else if n, _ := res.RowsAffected(); n > 0 {
		s.bumpRollupLocked("event:"+e.Kind.String(), e.TS)
	}

	// In-memory last-seen: the /status agents panel reads this per poll
	// (every 1–5s across all pids). The SQL MAX(ts) GROUP BY equivalent
	// measured 2–4s with ~400 live pids — past the client's 3s socket
	// timeout, which flipped the whole UI to "Disconnected" every poll.
	// One map assignment here replaces the scan entirely.
	if s.lastSeen == nil {
		s.lastSeen = map[int32]string{}
	}
	if cur, ok := s.lastSeen[e.PID]; !ok || tsStr > cur {
		s.lastSeen[e.PID] = tsStr
	}

	s.insertCount++
	if s.insertCount%1000 == 0 {
		s.pruneEventsLocked()
		s.pruneRollupLocked()
		s.pruneSessionsLocked()
	}
}

func (s *Store) PruneEvents() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneEventsLocked()
}

func (s *Store) pruneEventsLocked() {
	// Time-based per kind first (datetime() normalizes any legacy local-offset
	// ts values), then per-kind row budgets as a pure backstop. Every kind
	// present in the table is capped on its own budget (kindBudgets, else
	// defaultKindBudget), so one kind's volume never evicts another kind's
	// rows. Time retention still applies to every kind.
	conn := s.connRetention
	if conn <= 0 {
		conn = DefaultConnEventRetention
	}
	other := s.eventRetention
	if other <= 0 {
		other = DefaultEventRetention
	}
	now := time.Now().UTC()
	connCutoff := now.Add(-conn).Format(time.RFC3339Nano)
	otherCutoff := now.Add(-other).Format(time.RFC3339Nano)
	_, _ = s.db.Exec(`DELETE FROM events WHERE kind IN (?, ?) AND datetime(ts) < datetime(?)`,
		int(event.KindConnOpen), int(event.KindConnClose), connCutoff)
	_, _ = s.db.Exec(`DELETE FROM events WHERE kind NOT IN (?, ?) AND datetime(ts) < datetime(?)`,
		int(event.KindConnOpen), int(event.KindConnClose), otherCutoff)
	rows, err := s.db.Query(`SELECT DISTINCT kind FROM events`)
	if err != nil {
		return
	}
	var kinds []int
	for rows.Next() {
		var k int
		if rows.Scan(&k) == nil {
			kinds = append(kinds, k)
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("store: prune kinds: %v", err)
	}
	rows.Close()
	for _, k := range kinds {
		_, _ = s.db.Exec(`DELETE FROM events WHERE kind = ? AND id NOT IN
			(SELECT id FROM events WHERE kind = ? ORDER BY id DESC LIMIT ?)`, k, k, kindBudget(k))
	}
}

// kindBudgets: per-kind row budgets, the backstop under time retention. Each
// kind is capped on its own, so a burst in one kind (file opens during a
// build) can never evict another kind's rows (hook activity, connections,
// transcript hits). Sized so a week of heavy agent work fits.
var kindBudgets = map[int]int{
	int(event.KindFileOpen):      40000,
	int(event.KindFileWrite):     10000,
	int(event.KindFileDelete):    2000,
	int(event.KindExec):          10000,
	int(event.KindTCCModify):     1000,
	int(event.KindConnOpen):      5000,
	int(event.KindConnClose):     5000,
	int(event.KindTranscriptHit): 2000,
	int(event.KindPluginAction):  10000,
	int(event.KindProxyHit):      2000,
	int(event.KindGuardPrompt):   2000,
	int(event.KindGuardResolved): 2000,
	int(event.KindToolCall):      50000,
	int(event.KindTurn):          20000,
	int(event.KindModelCall):     100000,
}

const defaultKindBudget = 5000 // any kind not listed above

// kindBudget is the row budget for one event kind.
func kindBudget(kind int) int {
	if b, ok := kindBudgets[kind]; ok {
		return b
	}
	return defaultKindBudget
}

// FlagFilter narrows a flag history query. A zero value returns the most recent
// flags — RecentFlags is exactly that. Since is any RFC3339 timestamp (any
// offset); it is compared with SQLite's datetime() so stored local-offset
// stamps and a UTC bound normalize to the same instant.
type FlagFilter struct {
	Agent       string // exact match; empty = any
	Rule        string // exact match; empty = any
	SessionID   string // exact match; empty = any
	MinSeverity int    // severity >= this; 0 = any
	Since       string // ts >= this; empty = any
	Limit       int    // 0 = 50
	// Unacted excludes acknowledged (reviewed/dismissed) flags — a flag the
	// operator already closed must not keep demanding attention (posture).
	Unacted bool
}

// EventFilter narrows an event history query. Kind is a pointer because kind 0
// (KindFileOpen) is a valid filter value distinct from "not set".
type EventFilter struct {
	Kind       *int   // exact kind; nil = any
	PID        int32  // exact pid; 0 = any
	SessionID  string // exact session; "" = any
	RemoteHost string // exact remote host; "" = any
	Since      string // ts >= this; empty = any
	Until      string // ts <= this; empty = any
	Limit      int    // 0 = 50
}

func (s *Store) RecentFlags(limit int) []model.Flag {
	return s.QueryFlags(FlagFilter{Limit: limit})
}

// GetFlag fetches one flag by ID (for the re-triage endpoint). Absent ID →
// ok=false; the caller answers 404 rather than re-enqueueing a ghost.
// AcknowledgeRuleHost marks every UNacknowledged flag of `rule` whose
// evidence cites `host` as acted-upon. Called when the operator mutes a
// rule+host pair: the mute suppresses future flags AND the existing ones
// leave the critical list — otherwise "ignore" looks like it did nothing.
// Idempotent; returns the number of flags newly acknowledged.
func (s *Store) AcknowledgeRuleHost(rule, host string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(
		`SELECT id, evidence FROM flags WHERE rule = ? AND (acknowledged IS NULL OR acknowledged = '')`, rule)
	if err != nil {
		log.Printf("store: acknowledge-rule-host query error: %v", err)
		return 0
	}
	defer rows.Close()
	type pair struct{ id, ev string }
	var candidates []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.id, &p.ev); err == nil {
			candidates = append(candidates, p)
		}
	}
	rows.Close()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	n := 0
	for _, c := range candidates {
		// host "*" is the rule-level disposition: every open flag of the rule
		// leaves the list, not just those citing one host.
		if host != "*" && !evidenceCitesHost(c.ev, host) {
			continue
		}
		if _, err := s.db.Exec(`UPDATE flags SET acknowledged = ? WHERE id = ?`, now, c.id); err == nil {
			n++
		}
	}
	return n
}

// evidenceCitesHost: evidence JSON contains host as a connection target,
// localhost-alias aware.
func evidenceCitesHost(evidenceJSON, host string) bool {
	if host == "" {
		return false
	}
	var items []model.EvidenceItem
	_ = json.Unmarshal([]byte(evidenceJSON), &items)
	want := strings.ToLower(host)
	isLocal := want == "localhost" || want == "127.0.0.1" || want == "::1" || strings.HasPrefix(want, "127.")
	for _, item := range items {
		line := item.Text
		if line == "" {
			line = item.String()
		}
		idx := strings.Index(line, "connected to ")
		if idx < 0 {
			continue
		}
		rest := line[idx+len("connected to "):]
		if at := strings.Index(rest, " at "); at >= 0 {
			rest = rest[:at]
		}
		h := strings.TrimSuffix(rest, "") // host:port
		if h == "" {
			continue
		}
		// Strip port (IPv6-bracket aware).
		if strings.HasPrefix(h, "[") {
			if end := strings.Index(h, "]"); end > 0 {
				h = h[1:end]
			}
		} else if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i:], "]") && !strings.Contains(h, "::") {
			host2 := h[:i]
			if !strings.Contains(host2, ":") {
				h = host2
			}
		}
		h = strings.ToLower(h)
		if h == want {
			return true
		}
		if isLocal && (h == "localhost" || h == "127.0.0.1" || h == "::1" || strings.HasPrefix(h, "127.")) {
			return true
		}
	}
	return false
}

// AcknowledgeFlag marks a flag acted-upon: it stops counting as critical
// and renders dimmed. Idempotent (re-ack is a no-op success).
func (s *Store) AcknowledgeFlag(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(
		`UPDATE flags SET acknowledged = ? WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		log.Printf("store: acknowledge flag error: %v", err)
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

func (s *Store) GetFlag(id string) (model.Flag, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.db.QueryRow(
		`SELECT id, rule, severity, ts, pid, agent, session_id, workspace, evidence, acknowledged FROM flags WHERE id = ?`, id)
	var fl model.Flag
	var tsStr, evStr string
	var sessionID, workspace sql.NullString
	var ack sql.NullString
	if err := row.Scan(&fl.ID, &fl.Rule, &fl.Severity, &tsStr, &fl.PID, &fl.Agent, &sessionID, &workspace, &evStr, &ack); err != nil {
		return model.Flag{}, false
	}
	fl.SessionID = sessionID.String
	fl.Workspace = workspace.String
	fl.Acknowledged = ack.String != ""
	fl.TS, _ = time.Parse(time.RFC3339Nano, tsStr)
	_ = json.Unmarshal([]byte(evStr), &fl.Evidence)
	return fl, true
}

func (s *Store) QueryFlags(f FlagFilter) []model.Flag {
	s.mu.Lock()
	defer s.mu.Unlock()

	q := `SELECT id, rule, severity, ts, pid, agent, session_id, workspace, evidence, acknowledged FROM flags WHERE 1=1`
	var args []any
	if f.Agent != "" {
		q += " AND agent = ?"
		args = append(args, f.Agent)
	}
	if f.Rule != "" {
		q += " AND rule = ?"
		args = append(args, f.Rule)
	}
	if f.SessionID != "" {
		q += " AND session_id = ?"
		args = append(args, f.SessionID)
	}
	if f.MinSeverity > 0 {
		q += " AND severity >= ?"
		args = append(args, f.MinSeverity)
	}
	if f.Since != "" {
		q += " AND datetime(ts) >= datetime(?)"
		args = append(args, f.Since)
	}
	if f.Unacted {
		q += " AND (acknowledged IS NULL OR acknowledged = '')"
	}
	// Order by the normalized instant, not the raw RFC3339 text: local-offset
	// stamps sort wrong lexicographically across a DST change, which with LIMIT
	// can drop the truly-newest rows.
	q += " ORDER BY datetime(ts) DESC, ts DESC LIMIT ?"
	args = append(args, normalizeLimit(f.Limit))

	rows, err := s.db.Query(q, args...)
	if err != nil {
		log.Printf("store: query flags error: %v", err)
		return nil
	}
	defer rows.Close()

	flags := []model.Flag{}
	for rows.Next() {
		var fl model.Flag
		var tsStr, evStr string
		var sessionID, workspace sql.NullString
		var ack sql.NullString
		if err := rows.Scan(&fl.ID, &fl.Rule, &fl.Severity, &tsStr, &fl.PID, &fl.Agent, &sessionID, &workspace, &evStr, &ack); err == nil {
			fl.SessionID = sessionID.String
			fl.Workspace = workspace.String
			fl.TS, _ = time.Parse(time.RFC3339Nano, tsStr)
			fl.Acknowledged = ack.String != ""
			_ = json.Unmarshal([]byte(evStr), &fl.Evidence)
			flags = append(flags, fl)
		}
	}
	// A mid-cursor error must not be served as a complete history.
	if err := rows.Err(); err != nil {
		log.Printf("store: flags cursor error (result may be truncated): %v", err)
	}
	s.attachAdvisorLocked(flags)
	return flags
}

// rollupBucket is the UTC hour key for the rollup table.
func rollupBucket(t time.Time) string {
	return t.UTC().Truncate(time.Hour).Format("2006-01-02T15")
}

// rollupRetention bounds the rollup table (hourly buckets, a handful of kinds
// — 30 days ≈ a few thousand rows).
const rollupRetention = 30 * 24 * time.Hour

// bumpRollupLocked increments one hourly counter. Caller holds mu. Pruning is
// driven by PutEvent's existing cadence (see pruneEventsLocked call site).
func (s *Store) bumpRollupLocked(kind string, ts time.Time) {
	_, err := s.db.Exec(
		`INSERT INTO rollup_hourly (bucket, kind, count) VALUES (?, ?, 1)
		 ON CONFLICT(bucket, kind) DO UPDATE SET count = count + 1`,
		rollupBucket(ts), kind,
	)
	if err != nil {
		log.Printf("store: rollup bump failed (%s): %v", kind, err)
	}
}

// pruneRollupLocked drops expired buckets (called on PutEvent's prune cadence).
func (s *Store) pruneRollupLocked() {
	cutoff := rollupBucket(time.Now().Add(-rollupRetention))
	if _, err := s.db.Exec(`DELETE FROM rollup_hourly WHERE bucket < ?`, cutoff); err != nil {
		log.Printf("store: rollup prune failed: %v", err)
	}
}

// RollupPoint is one (bucket, kind) counter.
type RollupPoint struct {
	Bucket string `json:"bucket"` // UTC hour "2006-01-02T15"
	Kind   string `json:"kind"`
	Count  int    `json:"count"`
}

// RollupRange returns hourly counters since the given time (UTC).
func (s *Store) RollupRange(since time.Time) []RollupPoint {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(
		`SELECT bucket, kind, count FROM rollup_hourly WHERE bucket >= ? ORDER BY bucket`,
		rollupBucket(since),
	)
	if err != nil {
		log.Printf("store: rollup range error: %v", err)
		return nil
	}
	defer rows.Close()
	out := []RollupPoint{}
	for rows.Next() {
		var p RollupPoint
		if err := rows.Scan(&p.Bucket, &p.Kind, &p.Count); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// TrendFor computes the trend context for a flag's rule (and host, when the
// flag evidence names one).
func (s *Store) TrendFor(rule, host string) model.TrendContext {
	s.mu.Lock()
	defer s.mu.Unlock()
	var tc model.TrendContext
	now := time.Now().UTC()
	wk := now.Add(-7 * 24 * time.Hour).Format(time.RFC3339Nano)
	prior := now.Add(-14 * 24 * time.Hour).Format(time.RFC3339Nano)
	_ = s.db.QueryRow(
		`SELECT
		   SUM(CASE WHEN datetime(ts) >= datetime(?) THEN 1 ELSE 0 END),
		   SUM(CASE WHEN datetime(ts) >= datetime(?) AND datetime(ts) < datetime(?) THEN 1 ELSE 0 END)
		 FROM flags WHERE rule = ?`,
		wk, prior, wk, rule,
	).Scan(&tc.RuleLast7d, &tc.RulePrior7d)
	if host != "" {
		var first sql.NullString
		err := s.db.QueryRow(
			`SELECT MIN(ts) FROM events WHERE remote_host = ?`, host,
		).Scan(&first)
		if err == nil && first.Valid && first.String != "" {
			tc.HostKnown = true
			tc.HostFirstSeen = first.String
		}
	}
	return tc
}

// PutAdvisorVerdict stores (or replaces) the local advisor's verdict for a
// flag or incident. Advisory metadata only — nothing reads it back into an
// enforcement decision.
func (s *Store) PutAdvisorVerdict(subjectID, kind string, v model.AdvisorVerdict) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO advisor_verdicts
		 (subject_id, kind, assessment, confidence, rationale, suggested_action, model, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		subjectID, kind, v.Assessment, v.Confidence, v.Rationale, v.SuggestedAction, v.Model,
		v.CreatedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		log.Printf("store: failed to insert advisor verdict %s: %v", subjectID, err)
	}
}

// attachAdvisorLocked joins stored verdicts onto flags (caller holds mu).
func (s *Store) attachAdvisorLocked(flags []model.Flag) {
	for i := range flags {
		v, ok := s.advisorVerdictLocked(flags[i].ID, "flag")
		if ok {
			vv := v
			flags[i].Advisor = &vv
		}
	}
}

// advisorVerdictLocked fetches one verdict (caller holds mu).
func (s *Store) advisorVerdictLocked(subjectID, kind string) (model.AdvisorVerdict, bool) {
	var v model.AdvisorVerdict
	var conf sql.NullFloat64
	var assessment, action, modelName, created sql.NullString
	var rationale string
	err := s.db.QueryRow(
		`SELECT assessment, confidence, rationale, suggested_action, model, created_at
		 FROM advisor_verdicts WHERE subject_id = ? AND kind = ?`, subjectID, kind,
	).Scan(&assessment, &conf, &rationale, &action, &modelName, &created)
	if err != nil {
		return v, false
	}
	v.Assessment = assessment.String
	if conf.Valid {
		v.Confidence = conf.Float64
	}
	v.Rationale = rationale
	v.SuggestedAction = action.String
	v.Model = modelName.String
	v.CreatedAt, _ = time.Parse(time.RFC3339Nano, created.String)
	return v, true
}

func (s *Store) RecentEvents(limit int) []event.Event {
	return s.QueryEvents(EventFilter{Limit: limit})
}

func (s *Store) QueryEvents(f EventFilter) []event.Event {
	s.mu.Lock()
	defer s.mu.Unlock()

	q := `SELECT kind, ts, pid, exe_path, session_id, path, remote_host, remote_port, detail,
		tool, tool_status, duration_ms, model, tokens_in, tokens_out, cost_usd, call_id, provider FROM events WHERE 1=1`
	var args []any
	if f.Kind != nil {
		q += " AND kind = ?"
		args = append(args, *f.Kind)
	}
	if f.PID != 0 {
		q += " AND pid = ?"
		args = append(args, f.PID)
	}
	if f.SessionID != "" {
		q += " AND session_id = ?"
		args = append(args, f.SessionID)
	}
	if f.RemoteHost != "" {
		q += " AND remote_host = ?"
		args = append(args, f.RemoteHost)
	}
	if f.Since != "" {
		q += " AND datetime(ts) >= datetime(?)"
		args = append(args, f.Since)
	}
	if f.Until != "" {
		q += " AND datetime(ts) <= datetime(?)"
		args = append(args, f.Until)
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, normalizeLimit(f.Limit))

	rows, err := s.db.Query(q, args...)
	if err != nil {
		log.Printf("store: query events error: %v", err)
		return nil
	}
	defer rows.Close()

	events := []event.Event{}
	for rows.Next() {
		var e event.Event
		var kindInt int
		var tsStr string
		var tool, toolStatus, modelName, callID, provider sql.NullString
		var durMs, tokIn, tokOut sql.NullInt64
		var cost sql.NullFloat64
		if err := rows.Scan(&kindInt, &tsStr, &e.PID, &e.ExePath, &e.SessionID, &e.Path, &e.RemoteHost, &e.RemotePort, &e.Detail,
			&tool, &toolStatus, &durMs, &modelName, &tokIn, &tokOut, &cost, &callID, &provider); err == nil {
			e.Kind = event.Kind(kindInt)
			e.TS, _ = time.Parse(time.RFC3339Nano, tsStr)
			e.ToolName = tool.String
			e.ToolStatus = toolStatus.String
			e.DurationMs = durMs.Int64
			e.Model = modelName.String
			e.Provider = provider.String
			e.TokensIn = tokIn.Int64
			e.TokensOut = tokOut.Int64
			e.CostUSD = cost.Float64
			e.CallID = callID.String
			events = append(events, e)
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("store: events cursor error (result may be truncated): %v", err)
	}
	return events
}

func normalizeLimit(limit int) int {
	if limit <= 0 {
		return 50
	}
	if limit > 1000 {
		return 1000
	}
	return limit
}

// Nullable column helpers: zero values store as NULL so omitempty on read
// keeps "absent" distinct from "zero".
func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullInt(n int64) any {
	if n == 0 {
		return nil
	}
	return n
}

func nullFloat(f float64) any {
	if f == 0 {
		return nil
	}
	return f
}

func (s *Store) PutIncident(inc model.IncidentReport) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(inc)
	if err != nil {
		log.Printf("store: failed to marshal incident %s: %v", inc.ID, err)
		return
	}

	tsStr := inc.Timestamp.UTC().Format(time.RFC3339Nano)
	count := inc.AggregateCount
	if count == 0 {
		count = 1
	}
	flagIDs, _ := json.Marshal([]string{inc.FlagID})
	_, err = s.db.Exec(
		`INSERT OR REPLACE INTO incidents (id, flag_id, pid, risk, report_json, created_at, rule, session_id, subject, aggregate_count, last_flag_at, flag_ids) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		inc.ID, inc.FlagID, inc.PID, string(inc.Risk), string(data), tsStr,
		inc.Rule, inc.SessionID, inc.Subject, count, tsStr, string(flagIDs),
	)
	if err != nil {
		log.Printf("store: failed to insert incident %s: %v", inc.ID, err)
	}

	// Retention: a flag storm inserts a full report_json per incident; cap the
	// table so the always-on daemon's DB stays bounded (events are already capped).
	// Order by the normalized instant, not raw text: local-offset stamps sort
	// wrong lexicographically across a DST change.
	_, _ = s.db.Exec(`DELETE FROM incidents WHERE id NOT IN (SELECT id FROM incidents ORDER BY datetime(created_at) DESC, created_at DESC LIMIT ?)`, maxIncidents)
}

func (s *Store) GetIncident(id string) (*model.IncidentReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var reportJSON string
	err := s.db.QueryRow(`SELECT report_json FROM incidents WHERE id = ? OR flag_id = ?`, id, id).Scan(&reportJSON)
	if err != nil {
		return nil, err
	}

	var inc model.IncidentReport
	if err := json.Unmarshal([]byte(reportJSON), &inc); err != nil {
		return nil, err
	}
	if v, ok := s.advisorVerdictLocked(inc.ID, "incident"); ok {
		inc.AdvisorNarrative = v.Rationale
	}
	return &inc, nil
}

// IncidentIDForFlag returns the incident a flag opened or was aggregated
// into (newest first).
func (s *Store) IncidentIDForFlag(flagID string) (string, bool) {
	if flagID == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var id string
	err := s.db.QueryRow(
		`SELECT id FROM incidents
		 WHERE flag_id = ? OR EXISTS (SELECT 1 FROM json_each(COALESCE(flag_ids,'[]')) WHERE value = ?)
		 ORDER BY datetime(created_at) DESC LIMIT 1`,
		flagID, flagID,
	).Scan(&id)
	if err != nil {
		return "", false
	}
	return id, true
}

// FindOpenIncident returns the open (unresolved) incident matching the
// aggregation key — one incident per rule+session+subject; repeat flags
// become its evidence instead of minting duplicate reports.
func (s *Store) FindOpenIncident(rule, sessionID, subject string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var id string
	err := s.db.QueryRow(
		`SELECT id FROM incidents
		 WHERE COALESCE(rule,'') = ? AND COALESCE(session_id,'') = ? AND COALESCE(subject,'') = ?
		   AND COALESCE(status,'open') != 'resolved'
		 ORDER BY datetime(created_at) DESC LIMIT 1`,
		rule, sessionID, subject,
	).Scan(&id)
	if err != nil {
		return "", false
	}
	return id, true
}

// AggregateIntoIncident folds another flag into an existing incident: bumps
// the count, records the flag id as evidence, refreshes last_flag_at, and
// patches the served report_json so the UI reads current numbers. Returns
// the updated report (for the incident delta) — false when the row is gone.
func (s *Store) AggregateIntoIncident(id, flagID string, ts time.Time) (model.IncidentReport, bool) {
	if id == "" || flagID == "" {
		return model.IncidentReport{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var reportJSON, flagIDsRaw string
	var count int
	err := s.db.QueryRow(`SELECT report_json, COALESCE(flag_ids,'[]'), COALESCE(aggregate_count,1) FROM incidents WHERE id = ?`, id).
		Scan(&reportJSON, &flagIDsRaw, &count)
	if err != nil {
		return model.IncidentReport{}, false
	}
	var flagIDs []string
	_ = json.Unmarshal([]byte(flagIDsRaw), &flagIDs)
	flagIDs = append(flagIDs, flagID)
	count++
	tsStr := ts.UTC().Format(time.RFC3339Nano)

	var inc model.IncidentReport
	if err := json.Unmarshal([]byte(reportJSON), &inc); err == nil {
		inc.AggregateCount = count
		t := ts.UTC()
		inc.LastFlagAt = &t
		if data, err := json.Marshal(inc); err == nil {
			reportJSON = string(data)
		}
	}
	idsJSON, _ := json.Marshal(flagIDs)
	_, _ = s.db.Exec(`UPDATE incidents SET aggregate_count = ?, last_flag_at = ?, flag_ids = ?, report_json = ? WHERE id = ?`,
		count, tsStr, string(idsJSON), reportJSON, id)
	return inc, true
}

func (s *Store) RecentIncidents(limit int) []model.IncidentReport {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Resolved incidents stay in the audit trail but leave the active set:
	// the operator dismissed them, so they must not keep rendering as
	// critical rows in the popover.
	rows, err := s.db.Query(`SELECT report_json FROM incidents WHERE status != 'resolved' ORDER BY datetime(created_at) DESC, created_at DESC LIMIT ?`, normalizeLimit(limit))
	if err != nil {
		log.Printf("store: query incidents error: %v", err)
		return nil
	}
	defer rows.Close()

	list := []model.IncidentReport{}
	for rows.Next() {
		var reportJSON string
		if err := rows.Scan(&reportJSON); err == nil {
			var inc model.IncidentReport
			if err := json.Unmarshal([]byte(reportJSON), &inc); err == nil {
				list = append(list, inc)
			}
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("store: incidents cursor error (result may be truncated): %v", err)
	}
	s.attachNarrativesLocked(list)
	return list
}

// CriticalFlagsMissingAdvisor returns recent severity-3 flags that have no
// advisor verdict yet — the backfill set for when the advisor is enabled
// after flags already fired. Bounded by limit.
func (s *Store) CriticalFlagsMissingAdvisor(since time.Time, limit int) []model.Flag {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(
		`SELECT f.id, f.rule, f.severity, f.ts, f.pid, f.agent, f.session_id, f.evidence
		 FROM flags f
		 LEFT JOIN advisor_verdicts v ON v.subject_id = f.id AND v.kind = 'flag'
		 WHERE f.severity >= 3 AND v.subject_id IS NULL AND datetime(f.ts) >= datetime(?)
		 ORDER BY datetime(f.ts) DESC, f.ts DESC LIMIT ?`,
		since.UTC().Format(time.RFC3339Nano), normalizeLimit(limit),
	)
	if err != nil {
		log.Printf("store: backfill query error: %v", err)
		return nil
	}
	defer rows.Close()
	flags := []model.Flag{}
	for rows.Next() {
		var fl model.Flag
		var tsStr, evStr string
		var sessionID sql.NullString
		if err := rows.Scan(&fl.ID, &fl.Rule, &fl.Severity, &tsStr, &fl.PID, &fl.Agent, &sessionID, &evStr); err == nil {
			fl.SessionID = sessionID.String
			fl.TS, _ = time.Parse(time.RFC3339Nano, tsStr)
			_ = json.Unmarshal([]byte(evStr), &fl.Evidence)
			flags = append(flags, fl)
		}
	}
	return flags
}

// LastEventTimes returns the most recent event timestamp (RFC3339Nano, UTC)
// per pid, for the given pids — the "last used" signal the agents panel uses
// to tell stale trees from live ones. Reads the in-memory map maintained by
// PutEvent: O(pids) lookups, no table scan (the SQL MAX(ts) GROUP BY this
// replaced measured 2–4s at ~400 live pids, past the UI's 3s socket timeout).
// Events older than this daemon's lifetime are not included — last-seen is a
// liveness signal, and a fresh daemon honestly reports "no activity seen yet"
// until events flow again.
func (s *Store) LastEventTimes(pids []int32) map[int32]string {
	out := map[int32]string{}
	if len(pids) == 0 {
		return out
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range pids {
		if ts, ok := s.lastSeen[p]; ok {
			out[p] = ts
		}
	}
	return out
}

// AdvisorVerdictFor fetches one stored verdict (public read; absent = false).
func (s *Store) AdvisorVerdictFor(subjectID, kind string) (model.AdvisorVerdict, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.advisorVerdictLocked(subjectID, kind)
}

// attachNarrativesLocked joins advisor narratives onto incidents (caller
// holds mu).
func (s *Store) attachNarrativesLocked(list []model.IncidentReport) {
	for i := range list {
		if v, ok := s.advisorVerdictLocked(list[i].ID, "incident"); ok {
			list[i].AdvisorNarrative = v.Rationale
		}
	}
}

// PutAudit records a policy/control change. The store stamps the timestamp so
// callers never thread a clock. Audit is a long-lived security log — it keeps far
// more history than events — but it is still bounded: the entries are inserted by
// API-triggerable actions, so an unbounded table would let any process with
// socket access grow the DB without limit by looping mode toggles.
func (s *Store) PutAudit(a AuditEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ts := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.Exec(
		`INSERT INTO audit (ts, action, rule, from_mode, to_mode, detail) VALUES (?, ?, ?, ?, ?, ?)`,
		ts, a.Action, a.Rule, a.FromMode, a.ToMode, a.Detail,
	)
	if err != nil {
		log.Printf("store: failed to insert audit %s: %v", a.Action, err)
	}
	_, _ = s.db.Exec(`DELETE FROM audit WHERE id NOT IN (SELECT id FROM audit ORDER BY id DESC LIMIT ?)`, maxAudit)
}

func (s *Store) RecentAudit(limit int) []AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`SELECT id, ts, action, rule, from_mode, to_mode, detail FROM audit ORDER BY id DESC LIMIT ?`, normalizeLimit(limit))
	if err != nil {
		log.Printf("store: query audit error: %v", err)
		return nil
	}
	defer rows.Close()

	out := []AuditEntry{}
	for rows.Next() {
		var a AuditEntry
		if err := rows.Scan(&a.ID, &a.TS, &a.Action, &a.Rule, &a.FromMode, &a.ToMode, &a.Detail); err == nil {
			out = append(out, a)
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("store: audit cursor error (result may be truncated): %v", err)
	}
	return out
}

func (s *Store) PutResourceEpisode(episode resource.Episode) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	episode.ActivityStatus = "settling"
	enriched, enrichErr := s.attachResourceEpisodeActivity(ctx, episode)
	episode = enriched
	if enrichErr != nil {
		log.Printf("store: initial resource episode activity: %v", enrichErr)
	}
	payload, err := json.Marshal(episode)
	if err != nil {
		return fmt.Errorf("marshal resource episode: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin resource episode write: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO resource_episodes (captured_at, severity, session_key, episode_json) VALUES (?, ?, ?, ?)`,
		episode.CapturedAt.UTC().Format(time.RFC3339Nano), episode.Severity, episode.Session.Key, string(payload),
	); err != nil {
		return fmt.Errorf("insert resource episode: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM resource_episodes WHERE id NOT IN (SELECT id FROM resource_episodes ORDER BY id DESC LIMIT ?)`, maxResourceEpisodes); err != nil {
		return fmt.Errorf("prune resource episodes: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit resource episode: %w", err)
	}
	return nil
}

func (s *Store) attachResourceEpisodeActivity(ctx context.Context, episode resource.Episode) (resource.Episode, error) {
	end := episode.CapturedAt
	start := end.Add(-10 * time.Minute)
	var sampleStart time.Time
	for _, sample := range episode.Session.Samples {
		if !sample.At.IsZero() && sample.At.Before(end) && sample.At.After(start) && (sampleStart.IsZero() || sample.At.Before(sampleStart)) {
			sampleStart = sample.At
		}
	}
	if !sampleStart.IsZero() {
		start = sampleStart
	}
	if !episode.Session.RootStartedAt.IsZero() && episode.Session.RootStartedAt.After(start) {
		start = episode.Session.RootStartedAt
	}

	processes := make(map[int32]resource.Process, len(episode.Session.Processes))
	pids := make([]int32, 0, len(episode.Session.Processes))
	activities := append([]resource.EpisodeActivity(nil), episode.Activities...)
	activityKeys := make(map[string]struct{}, len(activities))
	for _, activity := range activities {
		activityKeys[resourceActivityKey(activity)] = struct{}{}
	}
	appendActivity := func(activity resource.EpisodeActivity) {
		key := resourceActivityKey(activity)
		if _, exists := activityKeys[key]; exists {
			return
		}
		activityKeys[key] = struct{}{}
		activities = append(activities, activity)
	}
	for _, process := range episode.Session.Processes {
		if process.PID <= 0 {
			continue
		}
		processes[process.PID] = process
		pids = append(pids, process.PID)
		if !process.StartedAt.IsZero() && !process.StartedAt.Before(start) && !process.StartedAt.After(end) {
			appendActivity(resource.EpisodeActivity{
				At: process.StartedAt, Kind: "process-start", PID: process.PID, Process: process.Name,
				Summary: truncateResourceActivity(process.Name+" started", 160),
			})
		}
	}
	if len(pids) == 0 || end.IsZero() {
		return resource.AttachEpisodeActivity(episode, activities), nil
	}

	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(pids)), ",")
	query := `SELECT kind, ts, pid, exe_path, path, remote_host, remote_port, detail
		FROM events WHERE pid IN (` + placeholders + `)
		AND datetime(ts) >= datetime(?) AND datetime(ts) <= datetime(?)
		ORDER BY datetime(ts) DESC, id DESC`
	args := make([]any, 0, len(pids)+2)
	for _, pid := range pids {
		args = append(args, pid)
	}
	args = append(args, start.UTC().Format(time.RFC3339Nano), end.UTC().Format(time.RFC3339Nano))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return resource.AttachEpisodeActivity(episode, activities), fmt.Errorf("query resource episode activity: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var e event.Event
		var kind int
		var ts string
		if err := rows.Scan(&kind, &ts, &e.PID, &e.ExePath, &e.Path, &e.RemoteHost, &e.RemotePort, &e.Detail); err != nil {
			continue
		}
		e.Kind = event.Kind(kind)
		e.TS, _ = time.Parse(time.RFC3339Nano, ts)
		process := processes[e.PID]
		if e.TS.Before(start) || e.TS.After(end) || (!process.StartedAt.IsZero() && e.TS.Before(process.StartedAt)) {
			continue
		}
		appendActivity(resource.EpisodeActivity{
			At: e.TS, Kind: resourceActivityKind(e.Kind), PID: e.PID, Process: process.Name,
			Summary: resourceActivitySummary(e),
		})
	}
	if err := rows.Err(); err != nil {
		return resource.AttachEpisodeActivity(episode, activities), fmt.Errorf("read resource episode activity: %w", err)
	}
	return resource.AttachEpisodeActivity(episode, activities), nil
}

func resourceActivityKey(activity resource.EpisodeActivity) string {
	return fmt.Sprintf("%d|%s|%d|%s", activity.At.UnixNano(), activity.Kind, activity.PID, activity.Summary)
}

func resourceActivityKind(kind event.Kind) string {
	switch kind {
	case event.KindExec:
		return "process"
	case event.KindPluginAction:
		return "tool"
	case event.KindFileOpen, event.KindFileWrite, event.KindFileDelete:
		return "file"
	case event.KindConnOpen, event.KindConnClose:
		return "network"
	case event.KindGuardPrompt, event.KindGuardResolved:
		return "guard"
	default:
		return "security"
	}
}

func resourceActivitySummary(e event.Event) string {
	var summary string
	switch e.Kind {
	case event.KindFileOpen:
		summary = "opened " + filepath.Base(e.Path)
	case event.KindFileWrite:
		summary = "wrote " + filepath.Base(e.Path)
	case event.KindFileDelete:
		summary = "deleted " + filepath.Base(e.Path)
	case event.KindExec:
		summary = filepath.Base(e.ExePath) + " executed"
	case event.KindConnOpen:
		summary = fmt.Sprintf("connected to %s:%d", e.RemoteHost, e.RemotePort)
	case event.KindConnClose:
		summary = fmt.Sprintf("closed connection to %s:%d", e.RemoteHost, e.RemotePort)
	case event.KindPluginAction:
		summary = e.Detail
	case event.KindGuardPrompt:
		summary = "guard prompted: " + e.Detail
	case event.KindGuardResolved:
		summary = "guard resolved: " + e.Detail
	case event.KindProxyHit:
		summary = "proxy rule matched: " + e.Detail
	case event.KindTranscriptHit:
		summary = "transcript rule matched: " + e.Detail
	case event.KindTCCModify:
		summary = "privacy controls changed"
	default:
		summary = e.Kind.String()
	}
	if strings.TrimSpace(summary) == "" {
		summary = e.Kind.String()
	}
	return truncateResourceActivity(summary, 160)
}

func truncateResourceActivity(value string, limit int) string {
	value = strings.TrimSpace(value)
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit]) + "…"
}

func (s *Store) RecentResourceEpisodes(limit int) []resource.Episode {
	s.mu.Lock()
	rows, err := s.db.Query(`SELECT id, episode_json FROM resource_episodes ORDER BY id DESC LIMIT ?`, normalizeLimit(limit))
	if err != nil {
		s.mu.Unlock()
		log.Printf("store: query resource episodes error: %v", err)
		return []resource.Episode{}
	}

	out := make([]resource.Episode, 0)
	payloads := make([]string, 0)
	for rows.Next() {
		var id int64
		var payload string
		if err := rows.Scan(&id, &payload); err != nil {
			continue
		}
		var episode resource.Episode
		if err := json.Unmarshal([]byte(payload), &episode); err != nil {
			log.Printf("store: decode resource episode %d: %v", id, err)
			continue
		}
		episode.ID = id
		out = append(out, episode)
		payloads = append(payloads, payload)
	}
	if err := rows.Err(); err != nil {
		log.Printf("store: resource episode cursor error (result may be truncated): %v", err)
	}
	rows.Close()
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for i := range out {
		if out[i].ActivityStatus == "complete" {
			continue
		}
		out[i] = s.refreshResourceEpisode(ctx, out[i].ID, payloads[i], out[i])
	}
	return out
}

// refreshResourceEpisode uses optimistic compare-and-swap updates. If another
// API reader enriches the same settling episode first, its activity is merged
// into the retry instead of being overwritten by a stale full-JSON write.
func (s *Store) refreshResourceEpisode(ctx context.Context, id int64, expectedPayload string, episode resource.Episode) resource.Episode {
	persistedFallback := episode
	accumulated := append([]resource.EpisodeActivity(nil), episode.Activities...)
	for attempt := 0; attempt < 3; attempt++ {
		enriched, enrichErr := s.attachResourceEpisodeActivity(ctx, episode)
		if enrichErr != nil {
			return persistedFallback
		}
		accumulated = append(accumulated[:0], enriched.Activities...)
		if !enriched.CapturedAt.IsZero() && time.Since(enriched.CapturedAt) >= episodeSettleWindow {
			enriched.ActivityStatus = "complete"
		}
		persisted := enriched
		persisted.ID = 0
		payload, err := json.Marshal(persisted)
		if err != nil {
			return persistedFallback
		}
		if string(payload) == expectedPayload {
			enriched.ID = id
			return enriched
		}
		result, err := s.db.ExecContext(ctx,
			`UPDATE resource_episodes SET episode_json = ? WHERE id = ? AND episode_json = ?`,
			string(payload), id, expectedPayload,
		)
		if err != nil {
			log.Printf("store: refresh resource episode %d: %v", id, err)
			return persistedFallback
		}
		if updated, _ := result.RowsAffected(); updated == 1 {
			enriched.ID = id
			return enriched
		}

		var latestPayload string
		if err := s.db.QueryRowContext(ctx, `SELECT episode_json FROM resource_episodes WHERE id = ?`, id).Scan(&latestPayload); err != nil {
			return persistedFallback
		}
		var latest resource.Episode
		if err := json.Unmarshal([]byte(latestPayload), &latest); err != nil {
			return persistedFallback
		}
		latest.ID = id
		persistedFallback = latest
		latest.Activities = mergeResourceActivities(latest.Activities, accumulated)
		episode = latest
		expectedPayload = latestPayload
	}
	// Heavy concurrent polling can exhaust the bounded retry loop. Return the
	// actual persisted row rather than an uncommitted merge that could exceed
	// the activity cap or disappear on the next read.
	var latestPayload string
	if err := s.db.QueryRowContext(ctx, `SELECT episode_json FROM resource_episodes WHERE id = ?`, id).Scan(&latestPayload); err == nil {
		var latest resource.Episode
		if json.Unmarshal([]byte(latestPayload), &latest) == nil {
			latest.ID = id
			return latest
		}
	}
	return persistedFallback
}

func mergeResourceActivities(existing, additional []resource.EpisodeActivity) []resource.EpisodeActivity {
	merged := append([]resource.EpisodeActivity(nil), existing...)
	seen := make(map[string]struct{}, len(merged))
	for _, activity := range merged {
		seen[resourceActivityKey(activity)] = struct{}{}
	}
	for _, activity := range additional {
		key := resourceActivityKey(activity)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, activity)
	}
	return merged
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.jsonlFile != nil {
		s.jsonlFile.Close()
		s.jsonlFile = nil
	}
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// GuardRule is one durable allow/deny decision for an agent's access to a
// directory-guard resource, keyed on (agent, rule_id). It records a decision
// and where it came from — never any secret value.
type GuardRule struct {
	ID        int64  `json:"id"`
	Agent     string `json:"agent"`
	RuleID    string `json:"rule_id"`
	Decision  string `json:"decision"` // "allow" | "deny"
	Source    string `json:"source"`   // "prompt" | "onboarding"
	CreatedAt string `json:"created_at"`
}

// GuardPathAllow is one operator-granted per-path exception: this exact
// path (and its descendants) is allowed for one agent under one rule —
// without widening the rule itself.
type GuardPathAllow struct {
	Agent     string `json:"agent"`
	RuleID    string `json:"rule_id"`
	Path      string `json:"path"`
	CreatedAt string `json:"created_at"`
}

// PutGuardPathAllow records one per-path allow (idempotent upsert).
func (s *Store) PutGuardPathAllow(g GuardPathAllow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.Exec(
		`INSERT INTO guard_path_allows (agent, rule_id, path, created_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(agent, rule_id, path) DO UPDATE SET created_at=excluded.created_at`,
		g.Agent, g.RuleID, g.Path, ts)
	if err != nil {
		log.Printf("store: put guard_path_allows error: %v", err)
	}
}

// guardPathAllowed answers whether path is allowed for agent/ruleID:
// exact match, or any ancestor-prefix match (an allow on ~/.ssh/config
// covers ~/.ssh/config/sub too — descendants inherit, siblings don't).
// Callers must hold s.mu.
func (s *Store) guardPathAllowedLocked(agent, ruleID, path string) bool {
	rows, err := s.db.Query(
		`SELECT path FROM guard_path_allows WHERE agent = ? AND rule_id = ?`,
		agent, ruleID,
	)
	if err != nil {
		log.Printf("store: query guard_path_allows error: %v", err)
		return false // fail closed: a read error is NOT an approval
	}
	defer rows.Close()
	for rows.Next() {
		var allowed string
		if err := rows.Scan(&allowed); err != nil {
			continue
		}
		if path == allowed || (len(path) > len(allowed) && path[:len(allowed)] == allowed && path[len(allowed)] == '/') {
			return true
		}
	}
	return false
}

// GuardPathAllowed is the public check used by /guard/decision. Path is
// cleaned so "a/b/" and "a//b" match their canonical form.
func (s *Store) GuardPathAllowed(agent, ruleID, path string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.guardPathAllowedLocked(agent, ruleID, filepath.Clean(path))
}

// ListGuardPathAllows returns recent per-path allows, newest first.
func (s *Store) ListGuardPathAllows(limit int) []GuardPathAllow {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(
		`SELECT agent, rule_id, path, created_at FROM guard_path_allows ORDER BY datetime(created_at) DESC LIMIT ?`,
		normalizeLimit(limit),
	)
	if err != nil {
		log.Printf("store: list guard_path_allows error: %v", err)
		return nil
	}
	defer rows.Close()
	out := []GuardPathAllow{}
	for rows.Next() {
		var g GuardPathAllow
		if err := rows.Scan(&g.Agent, &g.RuleID, &g.Path, &g.CreatedAt); err == nil {
			out = append(out, g)
		}
	}
	return out
}

// DeleteGuardPathAllow revokes one exception; removing an absent one is a no-op.
func (s *Store) DeleteGuardPathAllow(agent, ruleID, path string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(
		`DELETE FROM guard_path_allows WHERE agent = ? AND rule_id = ? AND path = ?`,
		agent, ruleID, path,
	)
	if err != nil {
		log.Printf("store: delete guard_path_allows error: %v", err)
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

func (s *Store) PutGuardRule(g GuardRule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.Exec(
		`INSERT INTO guard_rules (agent, rule_id, decision, source, created_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(agent, rule_id) DO UPDATE SET decision=excluded.decision, source=excluded.source, created_at=excluded.created_at`,
		g.Agent, g.RuleID, g.Decision, g.Source, ts,
	)
	if err != nil {
		log.Printf("store: failed to put guard rule %s/%s: %v", g.Agent, g.RuleID, err)
	}
}

func (s *Store) LookupGuardRule(agent, ruleID string) (GuardRule, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var g GuardRule
	err := s.db.QueryRow(
		`SELECT agent, rule_id, decision, source, created_at FROM guard_rules WHERE agent = ? AND rule_id = ?`,
		agent, ruleID,
	).Scan(&g.Agent, &g.RuleID, &g.Decision, &g.Source, &g.CreatedAt)
	if err != nil {
		return GuardRule{}, false
	}
	return g, true
}

func (s *Store) ListGuardRules(limit int) []GuardRule {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(
		`SELECT agent, rule_id, decision, source, created_at FROM guard_rules ORDER BY datetime(created_at) DESC LIMIT ?`,
		normalizeLimit(limit),
	)
	if err != nil {
		log.Printf("store: query guard_rules error: %v", err)
		return []GuardRule{}
	}
	defer rows.Close()
	out := []GuardRule{}
	for rows.Next() {
		var g GuardRule
		if err := rows.Scan(&g.Agent, &g.RuleID, &g.Decision, &g.Source, &g.CreatedAt); err == nil {
			out = append(out, g)
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("store: guard_rules cursor error (result may be truncated): %v", err)
	}
	return out
}

func (s *Store) DeleteGuardRule(agent, ruleID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`DELETE FROM guard_rules WHERE agent = ? AND rule_id = ?`, agent, ruleID)
	if err != nil {
		log.Printf("store: delete guard rule error: %v", err)
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

// IncidentWorkflow is the mutable state layered on top of a stored report.
// The report itself is immutable evidence; ack/resolve is operator bookkeeping.
type IncidentWorkflow struct {
	Status         string `json:"status"` // open | acknowledged | resolved
	AcknowledgedAt string `json:"acknowledged_at,omitempty"`
	ResolvedAt     string `json:"resolved_at,omitempty"`
	ResolutionNote string `json:"resolution_note,omitempty"`
}

// SetIncidentStatus transitions an incident's workflow state. Transitions are
// forward-only: open → acknowledged → resolved. Re-resolving is allowed (note
// is replaced); acknowledged_at is stamped only the first time.
func (s *Store) SetIncidentStatus(id, status, note string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var res sql.Result
	var err error
	switch status {
	case "acknowledged":
		res, err = s.db.Exec(
			`UPDATE incidents SET status='acknowledged',
				acknowledged_at=COALESCE(acknowledged_at, ?)
			 WHERE id = ? OR flag_id = ?`,
			time.Now().UTC().Format(time.RFC3339Nano), id, id)
	case "resolved":
		res, err = s.db.Exec(
			`UPDATE incidents SET status='resolved', resolved_at=?, resolution_note=?
			 WHERE id = ? OR flag_id = ?`,
			time.Now().UTC().Format(time.RFC3339Nano), note, id, id)
	case "open":
		res, err = s.db.Exec(
			`UPDATE incidents SET status='open', acknowledged_at=NULL, resolved_at=NULL, resolution_note=NULL
			 WHERE id = ? OR flag_id = ?`, id, id)
	default:
		return false, fmt.Errorf("invalid status %q (open|acknowledged|resolved)", status)
	}
	if err != nil {
		return false, err
	}
	// changes() is per-connection state and database/sql pools connections, so
	// a follow-up SELECT changes() can land on a different connection and
	// report 0 — RowsAffected() comes back with the UPDATE's own result.
	changed, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return changed > 0, nil
}

// IncidentStatus returns the workflow state for one incident.
func (s *Store) IncidentStatus(id string) (IncidentWorkflow, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var wf IncidentWorkflow
	var ack, res, note sql.NullString
	err := s.db.QueryRow(
		`SELECT status, acknowledged_at, resolved_at, resolution_note FROM incidents WHERE id = ? OR flag_id = ?`, id, id,
	).Scan(&wf.Status, &ack, &res, &note)
	if err != nil {
		return IncidentWorkflow{Status: "unknown"}, false
	}
	wf.AcknowledgedAt = ack.String
	wf.ResolvedAt = res.String
	wf.ResolutionNote = note.String
	return wf, wf.Status != ""
}
