package store

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
)

// initializeSchema upgrades legacy layouts atomically, in four ordered
// steps: create missing tables, add missing columns, migrate data, create
// indexes. Each column is checked independently so interrupted migrations
// from earlier releases can resume. Review metadata is additive to the v2
// read model; the earlier v3-aware compatibility build can still read
// detector evidence after rollback. testdata/schema.golden pins the result.
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
	if version > 3 {
		return fmt.Errorf("unsupported database schema version %d", version)
	}
	tableIndexes, err := createTables(tx)
	if err != nil {
		return err
	}
	if err := addMissingColumns(tx); err != nil {
		return err
	}
	if err := migrateData(tx, version); err != nil {
		return err
	}
	if err := createIndexes(tx, tableIndexes); err != nil {
		return err
	}
	if version < 3 {
		if _, err := tx.Exec(`PRAGMA user_version=3`); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// createTables creates every missing table and returns the CREATE INDEX
// statements listed beside them, which run after the column migration.
func createTables(tx *sql.Tx) ([]string, error) {
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
		`CREATE INDEX IF NOT EXISTS idx_flags_rule_agent ON flags(rule, agent);`,
		`CREATE INDEX IF NOT EXISTS idx_events_pid_ts ON events(pid, ts);`,
		`CREATE INDEX IF NOT EXISTS idx_events_kind_id ON events(kind, id);`,
		`CREATE INDEX IF NOT EXISTS idx_events_session_kind_id ON events(session_id, kind, id);`,
		`CREATE INDEX IF NOT EXISTS idx_events_host ON events(remote_host, id, ts) WHERE remote_host != '';`,
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
		decisionScopesSchema,
		sessionsSchema,
		`CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status, last_seen_at);`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_activity ON sessions(status, ` + timestampOrderExpr("last_seen_at") + ` DESC, id DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_root_identity ON sessions(root_pid, root_started_at);`,
		worktreeReposSchema,
		cleanupLogSchema,
		findingReviewsSchema,
		interventionsSchema,
		`CREATE INDEX IF NOT EXISTS idx_interventions_session ON interventions(session_id,requested_at);`,
		agentAsksSchema,
		scanCacheSchema,
		hookRunsSchema,
	}
	createQueries = append(createQueries, sysAgentSchemas...)

	var indexes []string
	for _, q := range createQueries {
		if strings.HasPrefix(q, `CREATE INDEX`) {
			indexes = append(indexes, q)
			continue
		}
		if _, err := tx.Exec(q); err != nil {
			return nil, fmt.Errorf("failed to init db schema: %w", err)
		}
	}
	return indexes, nil
}

type column struct{ name, typ string }

// addColumns adds each missing column to table in order; a column an
// earlier release or an interrupted upgrade already added is left as it is.
// Checked via PRAGMA so a fresh database logs no duplicate-column errors.
func addColumns(tx *sql.Tx, table string, cols ...column) error {
	for _, c := range cols {
		var n int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?`, table, c.name).Scan(&n); err != nil {
			return fmt.Errorf("inspect %s.%s: %w", table, c.name, err)
		}
		if n > 0 {
			continue
		}
		if _, err := tx.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + c.name + ` ` + c.typ); err != nil {
			return fmt.Errorf("migrate %s.%s: %w", table, c.name, err)
		}
		log.Printf("store: migrated %s: added %s column", table, c.name)
	}
	return nil
}

// addMissingColumns brings tables created by older releases (where CREATE
// TABLE IF NOT EXISTS is a no-op) up to the current columns. Each table's
// columns are added in the order they were introduced.
func addMissingColumns(tx *sql.Tx) error {
	for _, step := range []struct {
		table string
		cols  []column
	}{
		{"guard_decisions", []column{{"receipt_json", "TEXT NOT NULL DEFAULT '{}'"}}},
		{"hook_runs", []column{{"harness", "TEXT NOT NULL DEFAULT ''"}, {"evidence_json", "TEXT NOT NULL DEFAULT '{}'"}}},
		// NULL preserves legacy incidents as having no operator step reports.
		{"incidents", []column{{"remediation_json", "TEXT"}}},
		// Older resource tables retain their original rows and family key. A
		// nullable attribution column only applies to new exact-identity captures.
		{"resource_episodes", []column{{"session_id", "TEXT"}}},
		{"events", []column{{"session_id", "TEXT"}}},
		// flags.workspace (P5): the key for per-workspace notification scopes.
		{"flags", []column{{"session_id", "TEXT"}, {"workspace", "TEXT"}}},
		// sessions.origin: who spawned a session (an openclaw agent's Codex).
		{"sessions", []column{{"origin", "TEXT"}}},
		// Trace columns (P2).
		{"events", []column{{"tool", "TEXT"}, {"tool_status", "TEXT"}, {"duration_ms", "INTEGER"}, {"model", "TEXT"},
			{"tokens_in", "INTEGER"}, {"tokens_out", "INTEGER"}, {"cost_usd", "REAL"}, {"call_id", "TEXT"}, {"provider", "TEXT"},
			{"record", "INTEGER NOT NULL DEFAULT 0"}}},
		// Flags gain an acknowledged marker: when the operator acts on a flag
		// (applies any disposition), the flag stops counting as critical and
		// dims in the UI — "acted upon" is a first-class state. Then the
		// daemon's own acknowledge reason, the raising process snapshot (JSON),
		// so a finding still names its process after the process exits, and
		// the repeats folded into the flag.
		{"flags", []column{{"acknowledged", "TEXT"}, {"ack_reason", "TEXT"}, {"process", "TEXT"}, {"repeats", "INTEGER"}, {"last_seen", "TEXT"}}},
		// Incidents workflow columns: the acknowledge/resolve endpoints write
		// status/acknowledged_at/resolved_at/resolution_note; without them
		// those writes fail with "no such column".
		{"incidents", []column{{"status", "TEXT DEFAULT 'open'"}, {"acknowledged_at", "TEXT"}, {"resolved_at", "TEXT"}, {"resolution_note", "TEXT"},
			{"rule", "TEXT"}, {"session_id", "TEXT"}, {"subject", "TEXT"}, {"aggregate_count", "INTEGER"}, {"last_flag_at", "TEXT"}, {"flag_ids", "TEXT"}}},
	} {
		if err := addColumns(tx, step.table, step.cols...); err != nil {
			return err
		}
	}
	return nil
}

// migrateData rewrites rows an older release stored differently. It runs
// after the columns exist and before indexes that depend on the rewrite.
func migrateData(tx *sql.Tx, version int) error {
	// Antigravity transcript sessions were stored as harness "agy", its CLI
	// name; the agent (config, tagger, app) is "antigravity".
	if res, err := tx.Exec(`UPDATE sessions SET harness = 'antigravity' WHERE harness = 'agy'`); err != nil {
		return fmt.Errorf("rename agy sessions: %w", err)
	} else if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("store: renamed %d agy sessions to antigravity", n)
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
	// Earlier upgrades added status without the fresh schema's open default.
	// Initialize only untouched legacy workflows; recorded decisions and
	// malformed current-schema workflows must remain subject to strict reads.
	var legacyIncidentDefault bool
	if err := tx.QueryRow(`SELECT dflt_value IS NULL FROM pragma_table_info('incidents') WHERE name='status'`).Scan(&legacyIncidentDefault); err != nil {
		return fmt.Errorf("inspect incident workflow default: %w", err)
	}
	if legacyIncidentDefault {
		if _, err := tx.Exec(`UPDATE incidents SET status='open' WHERE status IS NULL
			AND COALESCE(acknowledged_at,'')='' AND COALESCE(resolved_at,'')='' AND COALESCE(resolution_note,'')=''`); err != nil {
			return fmt.Errorf("initialize legacy incident workflows: %w", err)
		}
	}
	return nil
}

// createIndexes creates or repairs every index once the columns they cover
// exist, then the ones listed beside the tables.
func createIndexes(tx *sql.Tx, tableIndexes []string) error {
	for _, q := range []string{
		`CREATE INDEX IF NOT EXISTS idx_hook_runs_session_time ON hook_runs(session_id, ` + timestampOrderExpr("ts") + ` DESC, run_id DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_resource_episodes_session_at ON resource_episodes(session_id, captured_at, id)`,
		// Record rows are pruned on their own budget; the partial index keeps
		// that walk off the bulk rows.
		`CREATE INDEX IF NOT EXISTS idx_events_record ON events(kind, id) WHERE record = 1;`,
		// One row per harness tool call: a completion (same session+call_id)
		// upserts the start row instead of appending a second. A plain UNIQUE
		// index (not partial) so ON CONFLICT(session_id, call_id) resolves;
		// SQLite treats NULL call_ids as distinct, so non-tool events (NULL)
		// never collide.
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_events_call ON events(session_id, call_id);`,
	} {
		if _, err := tx.Exec(q); err != nil {
			return fmt.Errorf("create schema index: %w", err)
		}
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
	for _, q := range []string{
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_events_turn_dedupe ON events(kind,session_id,ts) WHERE kind=13 AND session_id!=''`,
		traceActivityIndexSQL,
		sessionActivityIndexSQL,
		// Incident indexes follow the column migration: findOpenIncidentSQL's
		// expressions and lookups by flag id.
		`CREATE INDEX IF NOT EXISTS idx_incidents_open_key ON incidents(COALESCE(rule,''), COALESCE(session_id,''), COALESCE(subject,''));`,
		`CREATE INDEX IF NOT EXISTS idx_incidents_flag ON incidents(flag_id);`,
	} {
		if _, err := tx.Exec(q); err != nil {
			return fmt.Errorf("create schema index: %w", err)
		}
	}
	if _, err := tx.Exec(flagTimeIndexSQL); err != nil {
		log.Printf("store: flag time index skipped, retention and lists scan instead: %v", err)
	}
	if _, err := tx.Exec(incidentRetentionIndexSQL); err != nil {
		log.Printf("store: incident time index skipped, retention and lists scan instead: %v", err)
	}
	if err := createMemoryIndexes(tx); err != nil {
		return err
	}
	// An earlier build created idx_events_host on (remote_host, ts), which
	// sorts a host's rows for the newest-first list; rebuild it below.
	var hostIdxSQL string
	if err := tx.QueryRow(`SELECT COALESCE(sql,'') FROM sqlite_master WHERE type='index' AND name='idx_events_host'`).Scan(&hostIdxSQL); err == nil &&
		!strings.Contains(hostIdxSQL, "remote_host, id, ts") {
		if _, err := tx.Exec(`DROP INDEX idx_events_host`); err != nil {
			return fmt.Errorf("drop stale host index: %w", err)
		}
		log.Printf("store: rebuilding idx_events_host on (remote_host, id, ts)")
	}
	for _, q := range tableIndexes {
		if _, err := tx.Exec(q); err != nil {
			return fmt.Errorf("create schema index: %w", err)
		}
	}
	return nil
}
