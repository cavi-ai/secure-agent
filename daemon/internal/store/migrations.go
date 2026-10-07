package store

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
)

// initializeSchema upgrades legacy layouts atomically. Each column is checked
// independently so interrupted migrations from earlier releases can resume.
func initializeSchema(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err := tx.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version > 2 {
		return fmt.Errorf("unsupported database schema version %d", version)
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
		`CREATE INDEX IF NOT EXISTS idx_flags_pid ON flags(pid);`,
		`CREATE INDEX IF NOT EXISTS idx_flags_time ON flags(datetime(ts), ts);`,
		`CREATE INDEX IF NOT EXISTS idx_flags_rule_agent ON flags(rule, agent);`,
		`CREATE INDEX IF NOT EXISTS idx_events_pid_ts ON events(pid, ts);`,
		`CREATE INDEX IF NOT EXISTS idx_events_kind_id ON events(kind, id);`,
		`CREATE INDEX IF NOT EXISTS idx_events_session_kind_id ON events(session_id, kind, id);`,
		`CREATE INDEX IF NOT EXISTS idx_events_host ON events(remote_host, ts) WHERE remote_host != '';`,
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
		// Local-advisor plans, keyed by subject ("flag:<id>", "incident:<id>",
		// "file:<path>"); the plan JSON carries its evidence key.
		`CREATE TABLE IF NOT EXISTS advisor_plans (
			subject_id TEXT PRIMARY KEY,
			plan_json TEXT,
			created_at TEXT
		);`,
		// Operator labels: every judgment (allow, mute, guard answer, kill,
		// explicit mark) on a finding's subject, for similar-case recall.
		`CREATE TABLE IF NOT EXISTS operator_labels (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			kind TEXT, rule TEXT, agent TEXT, pattern TEXT,
			label TEXT, reason TEXT, source TEXT, created_at TEXT
		);`,
		`CREATE INDEX IF NOT EXISTS idx_operator_labels_agent_pattern ON operator_labels(agent, pattern);`,
		`CREATE INDEX IF NOT EXISTS idx_operator_labels_rule ON operator_labels(rule);`,
		`CREATE TABLE IF NOT EXISTS resource_episodes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			captured_at TEXT NOT NULL,
			severity TEXT NOT NULL,
			session_key TEXT NOT NULL,
			session_id TEXT,
			episode_json TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_resource_episodes_captured_at ON resource_episodes(captured_at);`,
		egressEpisodesSchema,
		expectedEgressSchema,
		guardDecisionsSchema,
		sessionsSchema,
		`CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status, last_seen_at);`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_activity ON sessions(status, ` + timestampOrderExpr("last_seen_at") + ` DESC, id DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_root_identity ON sessions(root_pid, root_started_at);`,
		worktreeReposSchema,
		cleanupLogSchema,
		agentAsksSchema,
		scanCacheSchema,
	}
	createQueries = append(createQueries, sysAgentSchemas...)

	var indexes []string
	for _, q := range createQueries {
		if strings.HasPrefix(q, `CREATE INDEX`) {
			indexes = append(indexes, q)
			continue
		}
		if _, err := tx.Exec(q); err != nil {
			return fmt.Errorf("failed to init db schema: %w", err)
		}
	}
	// Older resource tables retain their original rows and family key. A
	// nullable attribution column only applies to new exact-identity captures.
	var episodeSessionN int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('resource_episodes') WHERE name='session_id'`).Scan(&episodeSessionN); err != nil {
		return fmt.Errorf("failed to inspect resource_episodes.session_id: %w", err)
	}
	if episodeSessionN == 0 {
		if _, err := tx.Exec(`ALTER TABLE resource_episodes ADD COLUMN session_id TEXT`); err != nil {
			return fmt.Errorf("failed to migrate resource_episodes.session_id: %w", err)
		}
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_resource_episodes_session_at ON resource_episodes(session_id, captured_at, id)`); err != nil {
		return fmt.Errorf("failed to index resource_episodes.session_id: %w", err)
	}
	// Pre-session_id databases (CREATE TABLE IF NOT EXISTS is a no-op on them)
	// get the column added in place. Checked via PRAGMA so a fresh database
	// doesn't log a scary "duplicate column" error on every start.
	for _, table := range []string{"events", "flags"} {
		var n int
		if err := tx.QueryRow(
			`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name='session_id'`, table,
		).Scan(&n); err != nil {
			return fmt.Errorf("failed to inspect %s schema: %w", table, err)
		}
		if n == 0 {
			if _, err := tx.Exec(`ALTER TABLE ` + table + ` ADD COLUMN session_id TEXT`); err != nil {
				return fmt.Errorf("failed to migrate %s.session_id: %w", table, err)
			}
			log.Printf("store: migrated %s: added session_id column", table)
		}
	}
	// flags.workspace (P5): the key for per-workspace notification scopes.
	var wsN int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('flags') WHERE name='workspace'`).Scan(&wsN); err != nil {
		return fmt.Errorf("failed to inspect flags.workspace: %w", err)
	}
	if wsN == 0 {
		if _, err := tx.Exec(`ALTER TABLE flags ADD COLUMN workspace TEXT`); err != nil {
			return fmt.Errorf("failed to migrate flags.workspace: %w", err)
		}
		log.Printf("store: migrated flags: added workspace column")
	}
	// sessions.origin: who spawned a session (an openclaw agent's Codex).
	var originN int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name='origin'`).Scan(&originN); err != nil {
		return fmt.Errorf("failed to inspect sessions.origin: %w", err)
	}
	if originN == 0 {
		if _, err := tx.Exec(`ALTER TABLE sessions ADD COLUMN origin TEXT`); err != nil {
			return fmt.Errorf("failed to migrate sessions.origin: %w", err)
		}
		log.Printf("store: migrated sessions: added origin column")
	}
	// Trace columns (P2): older databases gain them in place.
	for _, col := range []string{"tool", "tool_status", "duration_ms", "model", "tokens_in", "tokens_out", "cost_usd", "call_id", "provider", "record"} {
		var n int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('events') WHERE name=?`, col).Scan(&n); err != nil {
			return fmt.Errorf("failed to inspect events schema: %w", err)
		}
		if n == 0 {
			typ := "TEXT"
			switch col {
			case "duration_ms", "tokens_in", "tokens_out":
				typ = "INTEGER"
			case "cost_usd":
				typ = "REAL"
			case "record":
				typ = "INTEGER NOT NULL DEFAULT 0"
			}
			if _, err := tx.Exec(`ALTER TABLE events ADD COLUMN ` + col + ` ` + typ); err != nil {
				return fmt.Errorf("failed to migrate events.%s: %w", col, err)
			}
			log.Printf("store: migrated events: added %s column", col)
		}
	}
	// Record rows are pruned on their own budget; the partial index keeps
	// that walk off the bulk rows.
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_events_record ON events(kind, id) WHERE record = 1;`); err != nil {
		return fmt.Errorf("failed to create events record index: %w", err)
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
	if _, err := tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_events_call ON events(session_id, call_id);`); err != nil {
		return fmt.Errorf("failed to create events call index: %w", err)
	}
	// A partial idx_events_call from an earlier build does not satisfy
	// ON CONFLICT(session_id, call_id). Detect the stale, same-name partial
	// index and replace it (indexes aren't IF-NOT-EXISTS-replaceable).
	var idxSQL string
	if err := tx.QueryRow(`SELECT COALESCE(sql,'') FROM sqlite_master WHERE type='index' AND name='idx_events_call'`).Scan(&idxSQL); err == nil {
		if strings.Contains(strings.ToUpper(idxSQL), "WHERE") {
			if _, err := tx.Exec(`DROP INDEX IF EXISTS idx_events_call`); err != nil {
				return fmt.Errorf("failed to drop stale call index: %w", err)
			}
			if _, err := tx.Exec(`CREATE UNIQUE INDEX idx_events_call ON events(session_id, call_id);`); err != nil {
				return fmt.Errorf("failed to recreate events call index: %w", err)
			}
			log.Printf("store: replaced partial idx_events_call with a full unique index")
		}
	}
	// Timestamp identity applies only to turns. Model calls with source IDs
	// use idx_events_call; ID-less calls remain distinct observations. Never
	// infer that equal usage or nearby timestamps identify the same API call.
	if version < 2 {
		if _, err := tx.Exec(`DROP INDEX IF EXISTS idx_events_turn_dedupe`); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM events WHERE kind=13 AND COALESCE(session_id,'')!='' AND id NOT IN (SELECT MIN(id) FROM events WHERE kind=13 GROUP BY session_id,ts)`); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_events_turn_dedupe ON events(kind,session_id,ts) WHERE kind=13 AND session_id!=''`); err != nil {
		return fmt.Errorf("create turn dedupe index: %w", err)
	}
	// Flags gain an acknowledged marker: when the operator acts on a flag
	// (applies any disposition), the flag stops counting as critical and
	// dims in the UI — "acted upon" is a first-class state, not an endless
	// red row. Same PRAGMA-checked migration pattern as session_id.
	var ackN int
	if err := tx.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('flags') WHERE name='acknowledged'`,
	).Scan(&ackN); err != nil {
		return fmt.Errorf("failed to inspect flags schema: %w", err)
	}
	if ackN == 0 {
		if _, err := tx.Exec(`ALTER TABLE flags ADD COLUMN acknowledged TEXT`); err != nil {
			return fmt.Errorf("failed to migrate flags.acknowledged: %w", err)
		}
		log.Printf("store: migrated flags: added acknowledged column")
	}
	// Flags gain the daemon's own acknowledge reason, the raising process
	// snapshot (JSON), so a finding still names its process after the
	// process exits, and the repeats folded into the flag.
	for _, col := range []string{"ack_reason", "process", "repeats", "last_seen"} {
		var n int
		if err := tx.QueryRow(
			`SELECT COUNT(*) FROM pragma_table_info('flags') WHERE name=?`, col,
		).Scan(&n); err != nil {
			return fmt.Errorf("failed to inspect flags schema: %w", err)
		}
		if n == 0 {
			typ := "TEXT"
			if col == "repeats" {
				typ = "INTEGER"
			}
			if _, err := tx.Exec(`ALTER TABLE flags ADD COLUMN ` + col + ` ` + typ); err != nil {
				return fmt.Errorf("failed to migrate flags.%s: %w", col, err)
			}
			log.Printf("store: migrated flags: added %s column", col)
		}
	}
	// Incidents workflow columns: the acknowledge/resolve endpoints write
	// status/acknowledged_at/resolved_at/resolution_note. Without this
	// migration those writes fail with "no such column" and the dashboard's
	// Acknowledge/Resolve buttons are dead (the exact "dismiss doesn't
	// work" dogfood complaint).
	for _, col := range []struct{ name, typ string }{
		{"status", "TEXT"}, {"acknowledged_at", "TEXT"}, {"resolved_at", "TEXT"}, {"resolution_note", "TEXT"},
		{"rule", "TEXT"}, {"session_id", "TEXT"}, {"subject", "TEXT"}, {"aggregate_count", "INTEGER"}, {"last_flag_at", "TEXT"}, {"flag_ids", "TEXT"},
	} {
		var n int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('incidents') WHERE name=?`, col.name).Scan(&n); err != nil {
			return fmt.Errorf("inspect incidents.%s: %w", col.name, err)
		}
		if n == 0 {
			if _, err := tx.Exec(`ALTER TABLE incidents ADD COLUMN ` + col.name + ` ` + col.typ); err != nil {
				return fmt.Errorf("migrate incidents.%s: %w", col.name, err)
			}
		}
	}
	// Incident indexes follow the column migration: findOpenIncidentSQL's
	// expressions, the retention order, and lookups by flag id.
	for _, q := range []string{
		`CREATE INDEX IF NOT EXISTS idx_incidents_open_key ON incidents(COALESCE(rule,''), COALESCE(session_id,''), COALESCE(subject,''));`,
		`CREATE INDEX IF NOT EXISTS idx_incidents_time ON incidents(datetime(created_at), created_at);`,
		`CREATE INDEX IF NOT EXISTS idx_incidents_flag ON incidents(flag_id);`,
	} {
		if _, err := tx.Exec(q); err != nil {
			return fmt.Errorf("failed to index incidents: %w", err)
		}
	}

	if err := createMemoryIndexes(tx); err != nil {
		return err
	}

	for _, q := range indexes {
		if _, err := tx.Exec(q); err != nil {
			return fmt.Errorf("create schema index: %w", err)
		}
	}
	if _, err := tx.Exec(`PRAGMA user_version=2`); err != nil {
		return err
	}
	return tx.Commit()
}
