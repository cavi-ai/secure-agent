package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/hostid"
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
	maxAdvisorPlans     = 2000  // one plan per subject
	maxOperatorLabels   = 5000  // operator judgments kept for recall
	episodeSettleWindow = 30 * time.Second
	// episodeSettleMax ends settling for a file feed that is still behind
	// the capture this long after it.
	episodeSettleMax = 10 * time.Minute
)

// Flag statements on hot paths, each served by an index (see Open).
const (
	// trimFlagsSQL deletes only the oldest flags past the cap, walking
	// idx_flags_time from the oldest end; no sort of the whole table.
	trimFlagsSQL = `DELETE FROM flags WHERE rowid IN (
		SELECT rowid FROM flags ORDER BY datetime(ts), ts
		LIMIT max(0, (SELECT COUNT(*) FROM flags) - ?))`
	// ruleCountsSQL counts a rule's flags for one agent in two windows; it
	// seeks idx_flags_rule_agent.
	ruleCountsSQL = `SELECT
		COALESCE(SUM(CASE WHEN datetime(ts) >= datetime(?) THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN datetime(ts) >= datetime(?) THEN 1 ELSE 0 END), 0)
		FROM flags WHERE rule = ? AND agent = ?`
	// reattributeFlagsSQL seeks idx_flags_pid.
	reattributeFlagsSQL = `UPDATE flags SET agent = ? WHERE pid = ? AND agent LIKE 'untagged:%' AND datetime(ts) >= datetime(?)`
	// trimIncidentsSQL deletes only the oldest incidents past the cap through
	// idx_incidents_time.
	trimIncidentsSQL = `DELETE FROM incidents WHERE rowid IN (
		SELECT rowid FROM incidents ORDER BY datetime(created_at), created_at
		LIMIT max(0, (SELECT COUNT(*) FROM incidents) - ?))`
	// findOpenIncidentSQL seeks idx_incidents_open_key; it runs for every
	// new flag.
	findOpenIncidentSQL = `SELECT id FROM incidents
		 WHERE COALESCE(rule,'') = ? AND COALESCE(session_id,'') = ? AND COALESCE(subject,'') = ?
		   AND COALESCE(status,'open') != 'resolved'
		 ORDER BY datetime(created_at) DESC LIMIT 1`
	// hostFirstSeenSQL seeks idx_events_host; the advisor runs it for each
	// flag, host and egress episode it triages. The partial index is usable
	// only when the statement repeats the index's empty-host exclusion.
	hostFirstSeenSQL = `SELECT MIN(ts) FROM events WHERE remote_host = ? AND remote_host != ''`
)

// Harness activity (hook and trace events) behind every /status, /snapshot
// and /posture: idx_events_trace_activity covers only those kinds, and the
// statement spells out the same kind list, which the partial index needs.
var (
	traceActivityKinds = fmt.Sprintf("%d, %d, %d, %d",
		event.KindPluginAction, event.KindToolCall, event.KindTurn, event.KindModelCall)
	traceActivityIndexSQL = `CREATE INDEX IF NOT EXISTS idx_events_trace_activity ON events(kind, ` + timestampOrderExpr("ts") + `, session_id, ts)
		WHERE kind IN (` + traceActivityKinds + `);
		DROP INDEX IF EXISTS idx_events_trace_ts;`
	// Session coverage reads each live session's newest hook, payload and
	// trace event with one seek per kind. Its statements spell out the same
	// kind list, which the partial index needs.
	sessionActivityKinds = fmt.Sprintf("%d, %d, %d, %d, %d",
		event.KindPluginAction, event.KindProxyHit, event.KindToolCall, event.KindTurn, event.KindModelCall)
	sessionActivityIndexSQL = `CREATE INDEX IF NOT EXISTS idx_events_session_activity ON events(session_id, kind, ` + timestampOrderExpr("ts") + `, ts)
		WHERE kind IN (` + sessionActivityKinds + `)`
	// Prefix each candidate with a fixed-width UTC sort key. Strip that key
	// after MAX so callers receive the original RFC3339 timestamp.
	harnessActivitySQL = fmt.Sprintf(`SELECT s.harness,
		substr(MAX(CASE WHEN e.kind = %d THEN %s || e.ts ELSE '' END),31),
		substr(MAX(CASE WHEN e.kind IN (%d, %d, %d) THEN %s || e.ts ELSE '' END),31)
		FROM events e JOIN sessions s ON s.id = e.session_id
		WHERE e.kind IN (%s) AND %s >= ? AND s.harness != ''
		GROUP BY s.harness`, event.KindPluginAction, timestampOrderExpr("e.ts"), event.KindToolCall, event.KindTurn, event.KindModelCall, timestampOrderExpr("e.ts"), traceActivityKinds, timestampOrderExpr("e.ts"))
)

// pruneMinInterval is the shortest gap between two insert-driven prunes.
var pruneMinInterval = 30 * time.Second

type Store struct {
	egressProjectionHealth egressProjectionHealth
	writeHealth            writeHealth
	mu                     sync.Mutex
	egressMu               sync.Mutex // serializes episode read-modify-write without blocking event state
	db                     *sql.DB
	flagMirror             *flagMirror
	insertCount            uint64
	reviewWrites           uint64
	guardDecisionWrites    atomic.Uint64
	// Test seam for the identity-to-insert boundary; nil in production.
	resourceEpisodeAfterLookup func()
	// openID is the newest event id when the store opened: rows above it
	// were written since this daemon started, whatever their own timestamp.
	openID int64
	// lastPrune gates the insert-driven prune to pruneMinInterval, so a
	// high-rate producer does not trigger it every 1000 inserts.
	lastPrune time.Time
	// Per-kind time-based retention. Socket churn (conn open/close) ages out
	// in hours; security-relevant kinds keep days. Count-based pruning stays
	// as a backstop — a busy machine must never let conn noise evict the
	// security record.
	connRetention  time.Duration
	eventRetention time.Duration
	// lastSeen[pid] = time of the most recent event for that pid,
	// maintained on insert so the /status agents join is O(pids) map lookups
	// instead of a MAX(ts) GROUP BY scan over the events table (measured
	// 2–4s at ~400 live pids — past the UI's 3s socket timeout).
	lastSeen map[int32]time.Time
	// allowlist returns the operator's approved hosts per agent (nil until
	// wired); TrendFor reads it for the advisor's host prompt.
	allowlist func() map[string][]string
	// fileFeed is on when an ES feed runs; fileFeedNewest is the event time
	// (Unix ns) of the newest ES event the drain loop has finished with.
	fileFeed       atomic.Bool
	fileFeedNewest atomic.Int64
}

// SetAllowlistSource wires the operator allowlist (agent -> hosts) that
// TrendFor reports as AllowedFor.
func (s *Store) SetAllowlistSource(fn func() map[string][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allowlist = fn
}

// TrackFileFeed marks an ES feed as running. ES rows are stored with their
// event time and can arrive minutes after it, so a resource episode keeps
// re-reading its activity until the feed has reached its capture.
func (s *Store) TrackFileFeed() {
	s.fileFeed.Store(true)
}

// NoteFileFeed advances the feed clock past an ES event the drain loop has
// stored or deliberately skipped.
func (s *Store) NoteFileFeed(at time.Time) {
	ns := at.UnixNano()
	for {
		cur := s.fileFeedNewest.Load()
		if ns <= cur || s.fileFeedNewest.CompareAndSwap(cur, ns) {
			return
		}
	}
}

// episodeSettled reports whether an episode's activity is final: the settle
// window has passed and the file feed has handled events from the capture
// on (or there is no feed or no event yet, or it is still behind
// episodeSettleMax later).
func (s *Store) episodeSettled(captured time.Time) bool {
	if captured.IsZero() {
		return false
	}
	age := time.Since(captured)
	if age < episodeSettleWindow {
		return false
	}
	if !s.fileFeed.Load() || age >= episodeSettleMax {
		return true
	}
	newest := s.fileFeedNewest.Load()
	return newest == 0 || newest >= captured.UnixNano()
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
		dsn = dsn + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(3000)&_pragma=analysis_limit(1000)"
	} else {
		dsn = ":memory:?_pragma=journal_mode(WAL)"
	}
	// Read-modify-write transactions reserve the writer before taking their
	// snapshot. A deferred read-to-write upgrade can fail with SQLITE_BUSY
	// immediately, bypassing busy_timeout when another connection writes.
	dsn += "&_txlock=immediate"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite: %w", err)
	}
	if dbPath == "" {
		// A :memory: database belongs to one connection. Additional pooled
		// connections would have neither its schema nor its stored evidence.
		db.SetMaxOpenConns(1)
	}

	if err := initializeSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize database schema: %w", err)
	}

	var mirror *flagMirror
	if jsonlPath != "" {
		var err error
		mirror, err = openFlagMirror(jsonlPath)
		if err != nil {
			log.Printf("store: warning: failed to open jsonl path %s: %v", jsonlPath, err)
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

	refreshPlannerStats(db)

	var openID int64
	_ = db.QueryRow(`SELECT COALESCE(MAX(id), 0) FROM events`).Scan(&openID)

	s := &Store{
		db:         db,
		flagMirror: mirror,
		openID:     openID,
	}
	if mirror != nil && mirror.file == nil {
		s.noteWrite("flag mirror", fmt.Errorf("mirror unavailable"))
	}
	if err := s.backfillFindingReviews(); err != nil {
		s.noteWrite("finding reviews", err)
	}
	return s, nil
}

// refreshPlannerStats keeps sqlite_stat1 current so the planner knows kind
// has a handful of values and pid or session_id a great many; without it a
// kind=? AND pid=? lookup walks every row of the kind through
// idx_events_kind_id. Bounded by analysis_limit; a no-op when the stats are
// current.
func refreshPlannerStats(db *sql.DB) {
	if _, err := db.Exec(`PRAGMA optimize=0x10002`); err != nil {
		log.Printf("store: planner stats: %v", err)
	}
}

// PutFlag reports the SQLite outcome. A mirror failure remains independently
// visible in write health and does not invalidate a successfully saved row.
func (s *Store) PutFlag(fl model.Flag) (result WriteResult, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	evJSON, err := json.Marshal(fl.Evidence)
	if err != nil {
		result.HealthChanged = s.noteWrite("flags", err)
		return result, err
	}
	tsStr := fl.TS.UTC().Format(time.RFC3339Nano)
	var procJSON sql.NullString
	if fl.Process != nil {
		b, marshalErr := json.Marshal(fl.Process)
		if marshalErr != nil {
			result.HealthChanged = s.noteWrite("flags", marshalErr)
			return result, marshalErr
		}
		procJSON = sql.NullString{String: string(b), Valid: true}
	}

	res, err := s.db.Exec(
		`INSERT OR REPLACE INTO flags (id, rule, severity, ts, pid, agent, session_id, workspace, evidence, process) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		fl.ID, fl.Rule, fl.Severity, tsStr, fl.PID, fl.Agent, fl.SessionID, fl.Workspace, string(evJSON), procJSON,
	)
	if err == nil {
		var n int64
		n, err = res.RowsAffected()
		if err == nil && n == 0 {
			err = fmt.Errorf("flag write affected no rows")
		}
	}
	result.HealthChanged = s.noteWrite("flags", err)
	if err != nil {
		log.Printf("store: failed to insert flag %s: %v", fl.ID, err)
		return result, err
	}
	result.Changed = true
	if fl.Rule == "sensitive-read-then-connect" {
		_, reviewErr := s.observeFindingReviewLocked(fl, model.AssessFinding(fl))
		result.HealthChanged = s.noteWrite("finding reviews", reviewErr) || result.HealthChanged
	}
	s.bumpRollupLocked(fmt.Sprintf("flag:s%d", fl.Severity), fl.TS)

	// Retention: flags are insert-only like events and must be capped too, or
	// an always-on daemon on a noisy host grows the DB without limit.
	_, _ = s.db.Exec(trimFlagsSQL, maxFlags)

	if s.flagMirror != nil {
		err := s.flagMirror.append(fl)
		result.HealthChanged = s.noteWrite("flag mirror", err) || result.HealthChanged
		if err != nil {
			log.Printf("store: flag mirror write failed: %v", err)
		}
	}
	return result, nil
}

// PutEvent reports whether SQLite changed a row. Intentional deduplication
// returns an unchanged result; it cannot clear an outstanding write fault.
func (s *Store) PutEvent(e event.Event) (result WriteResult, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tsStr := e.TS.UTC().Format(time.RFC3339Nano)
	var res sql.Result
	switch {
	case e.CallID != "" && e.Kind == event.KindModelCall:
		// One row per API call, keyed by its message id: Claude Code writes a
		// transcript record per content block, each repeating the id and
		// usage, and a restart mid-message or a re-read replays them. A repeat
		// keeps the row's first timestamp and raises its counts to the largest
		// seen; one that adds nothing changes nothing. Distinct IDs remain
		// distinct calls even when the source timestamps are equal.
		res, err = s.db.Exec(
			`INSERT INTO events (kind, ts, pid, exe_path, session_id, path, remote_host, remote_port, detail, tool, tool_status, duration_ms, model, tokens_in, tokens_out, cost_usd, provider, call_id, record)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(session_id, call_id) DO UPDATE SET
			   tokens_in  = MAX(COALESCE(events.tokens_in, 0),  COALESCE(excluded.tokens_in, 0)),
			   tokens_out = MAX(COALESCE(events.tokens_out, 0), COALESCE(excluded.tokens_out, 0)),
			   cost_usd   = MAX(COALESCE(events.cost_usd, 0),   COALESCE(excluded.cost_usd, 0))
			 WHERE COALESCE(excluded.tokens_in, 0)  > COALESCE(events.tokens_in, 0)
			    OR COALESCE(excluded.tokens_out, 0) > COALESCE(events.tokens_out, 0)
			    OR COALESCE(excluded.cost_usd, 0)   > COALESCE(events.cost_usd, 0)`,
			int(e.Kind), tsStr, e.PID, e.ExePath, e.SessionID, e.Path, e.RemoteHost, e.RemotePort, e.Detail,
			nullStr(e.ToolName), nullStr(e.ToolStatus), nullInt(e.DurationMs), nullStr(e.Model), nullInt(e.TokensIn), nullInt(e.TokensOut), nullFloat(e.CostUSD), nullStr(e.Provider), e.CallID, e.Record,
		)
	case e.CallID != "":
		// Tool calls are keyed by (session_id, call_id): the harness emits a
		// start (status "running") and later a completion for the SAME call,
		// and a transcript re-read can replay both. The upsert folds them into
		// one row — the start inserts, the completion updates status/duration
		// in place. Events with no call id (NULL) never match the unique index
		// and take the default branch.
		res, err = s.db.Exec(
			`INSERT INTO events (kind, ts, pid, exe_path, session_id, path, remote_host, remote_port, detail, tool, tool_status, duration_ms, model, tokens_in, tokens_out, cost_usd, call_id, record)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(session_id, call_id) DO UPDATE SET
			   tool_status = CASE WHEN excluded.tool_status != '' AND excluded.tool_status != 'running' AND (excluded.tool_status != 'incomplete' OR COALESCE(events.tool_status,'') IN ('','running','incomplete')) THEN excluded.tool_status ELSE events.tool_status END,
			   duration_ms = CASE WHEN excluded.duration_ms > 0 THEN excluded.duration_ms ELSE events.duration_ms END,
			   detail      = CASE
			     WHEN excluded.duration_ms > 0 AND events.detail = 'tool duration unavailable: start not retained' THEN ''
			     WHEN COALESCE(events.duration_ms, 0) > 0 AND excluded.detail = 'tool duration unavailable: start not retained' THEN events.detail
			     WHEN excluded.detail != '' THEN excluded.detail ELSE events.detail END,
			   tokens_in   = CASE WHEN excluded.tokens_in  > 0 THEN excluded.tokens_in  ELSE events.tokens_in  END,
			   tokens_out  = CASE WHEN excluded.tokens_out > 0 THEN excluded.tokens_out ELSE events.tokens_out END,
			   cost_usd    = CASE WHEN excluded.cost_usd   > 0 THEN excluded.cost_usd   ELSE events.cost_usd   END`,
			int(e.Kind), tsStr, e.PID, e.ExePath, e.SessionID, e.Path, e.RemoteHost, e.RemotePort, e.Detail,
			nullStr(e.ToolName), nullStr(e.ToolStatus), nullInt(e.DurationMs), nullStr(e.Model), nullInt(e.TokensIn), nullInt(e.TokensOut), nullFloat(e.CostUSD), e.CallID, e.Record,
		)
	default:
		// Turns dedupe on (kind, session_id, ts) — a
		// transcript re-read replays the same record and must not
		// double-count. INSERT OR IGNORE relies on the partial unique index
		// created at open. Model calls without IDs remain separate observations.
		verb := "INSERT"
		if e.Kind == event.KindTurn {
			verb = "INSERT OR IGNORE"
		}
		res, err = s.db.Exec(
			verb+` INTO events (kind, ts, pid, exe_path, session_id, path, remote_host, remote_port, detail, tool, tool_status, duration_ms, model, tokens_in, tokens_out, cost_usd, provider, record)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			int(e.Kind), tsStr, e.PID, e.ExePath, e.SessionID, e.Path, e.RemoteHost, e.RemotePort, e.Detail,
			nullStr(e.ToolName), nullStr(e.ToolStatus), nullInt(e.DurationMs), nullStr(e.Model), nullInt(e.TokensIn), nullInt(e.TokensOut), nullFloat(e.CostUSD), nullStr(e.Provider), e.Record,
		)
	}
	var n int64
	if err == nil {
		n, err = res.RowsAffected()
		if err == nil && n == 0 {
			var stored bool
			stored, err = s.eventNoopStoredLocked(e, tsStr)
			if err == nil && !stored {
				err = fmt.Errorf("event write affected no rows without a stored duplicate")
			}
		}
	}
	if err != nil {
		result.HealthChanged = s.noteWrite("events", err)
		log.Printf("store: failed to insert event: %v", err)
	} else if n > 0 {
		result.Changed = true
		result.HealthChanged = s.noteWrite("events", nil)
		s.bumpRollupLocked("event:"+e.Kind.String(), e.TS)
	}

	// In-memory last-seen: the /status agents panel reads this per poll
	// (every 1–5s across all pids). The SQL MAX(ts) GROUP BY equivalent
	// measured 2–4s with ~400 live pids — past the client's 3s socket
	// timeout, which flipped the whole UI to "Disconnected" every poll.
	// One map assignment here replaces the scan entirely.
	if s.lastSeen == nil {
		s.lastSeen = map[int32]time.Time{}
	}
	if cur, ok := s.lastSeen[e.PID]; !ok || e.TS.After(cur) {
		s.lastSeen[e.PID] = e.TS
	}

	s.insertCount++
	if s.insertCount%1000 == 0 && time.Since(s.lastPrune) >= pruneMinInterval {
		s.pruneEventsLocked()
		s.pruneRollupLocked()
		s.pruneSessionsLocked()
		refreshPlannerStats(s.db)
		s.lastPrune = time.Now()
	}
	return result, err
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
	// Distinct kinds by index skip-scan: one MIN(kind) seek per kind.
	rows, err := s.db.Query(`WITH RECURSIVE k(v) AS (
			SELECT MIN(kind) FROM events
			UNION ALL
			SELECT (SELECT MIN(kind) FROM events WHERE kind > k.v) FROM k WHERE k.v IS NOT NULL)
		SELECT v FROM k WHERE v IS NOT NULL`)
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
	// Keep each kind's newest budget rows: delete below the budget-th newest
	// id, except record rows. Fewer rows than the budget yield a NULL cutoff
	// and delete nothing. Record rows then keep their own newest
	// recordBudget, so the security record outlives a build's file flood.
	for _, k := range kinds {
		_, _ = s.db.Exec(`DELETE FROM events WHERE kind = ? AND record = 0 AND id <
			(SELECT id FROM events WHERE kind = ? ORDER BY id DESC LIMIT 1 OFFSET ?)`, k, k, kindBudget(k)-1)
		_, _ = s.db.Exec(`DELETE FROM events WHERE kind = ? AND record = 1 AND id <
			(SELECT id FROM events WHERE kind = ? AND record = 1 ORDER BY id DESC LIMIT 1 OFFSET ?)`, k, k, recordBudget-1)
	}
}

// recordBudget caps a kind's record rows (event.Record) — a backstop for an
// agent reading a sensitive path in a loop; time retention bounds them first.
var recordBudget = 20000

// ringKinds arrive faster than any fixed budget holds for a day under build
// load (measured: file opens 356–1,300/s, exec 35/s, file deletes 39/s, file
// writes 150,000 rows in under 16 h), so their newest budget rows cover
// minutes to hours. Only their record rows keep days.
var ringKinds = map[int]bool{
	int(event.KindFileOpen):   true,
	int(event.KindFileWrite):  true,
	int(event.KindFileDelete): true,
	int(event.KindExec):       true,
}

// RejudgeRecords clears the record mark on stored file rows that keep no
// longer counts, so rows marked under an older rule stop holding the record
// budget. A row that shares its pid and second with a stored flag is the
// flag's own event and stays marked. Returns how many rows it cleared.
func (s *Store) RejudgeRecords(keep func(event.Event) bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	flagged := map[string]bool{}
	frows, err := s.db.Query(`SELECT pid, COALESCE(ts,''), COALESCE(last_seen,'') FROM flags`)
	if err != nil {
		return 0
	}
	for frows.Next() {
		var pid int32
		var ts, last string
		if frows.Scan(&pid, &ts, &last) == nil {
			flagged[recordKey(pid, ts)] = true
			flagged[recordKey(pid, last)] = true
		}
	}
	frows.Close()
	rows, err := s.db.Query(`SELECT id, kind, pid, COALESCE(exe_path,''), COALESCE(path,''), ts FROM events
		WHERE record = 1 AND kind IN (?, ?, ?)`,
		int(event.KindFileOpen), int(event.KindFileWrite), int(event.KindFileDelete))
	if err != nil {
		return 0
	}
	var clear []int64
	for rows.Next() {
		var id int64
		var kind int
		var e event.Event
		var ts string
		if rows.Scan(&id, &kind, &e.PID, &e.ExePath, &e.Path, &ts) != nil {
			continue
		}
		e.Kind = event.Kind(kind)
		if !keep(e) && !flagged[recordKey(e.PID, ts)] {
			clear = append(clear, id)
		}
	}
	rows.Close()
	tx, err := s.db.Begin()
	if err != nil {
		return 0
	}
	n := 0
	for _, id := range clear {
		if _, err := tx.Exec(`UPDATE events SET record = 0 WHERE id = ?`, id); err == nil {
			n++
		}
	}
	if tx.Commit() != nil {
		return 0
	}
	return n
}

// recordKey is a pid and a UTC timestamp truncated to the second.
func recordKey(pid int32, ts string) string {
	if len(ts) > 19 {
		ts = ts[:19]
	}
	return fmt.Sprintf("%d|%s", pid, ts)
}

// kindBudgets: per-kind row budgets, the backstop under time retention. Each
// kind is capped on its own, so a burst in one kind (file opens during a
// build) can never evict another kind's rows (hook activity, connections,
// transcript hits). Kinds outside ringKinds are sized to hold a day at the
// measured rate (connection opens and closes 0.3/s).
var kindBudgets = map[int]int{
	int(event.KindFileOpen):      40000,
	int(event.KindFileWrite):     150000,
	int(event.KindFileDelete):    2000,
	int(event.KindExec):          10000,
	int(event.KindTCCModify):     1000,
	int(event.KindConnOpen):      30000,
	int(event.KindConnClose):     30000,
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

// ackRuleHostQuery selects the open flags of rule (for agent, when set); it
// seeks idx_flags_rule_agent.
func ackRuleHostQuery(rule, agent string) (string, []any) {
	q := `SELECT id, evidence FROM flags WHERE rule = ? AND (acknowledged IS NULL OR acknowledged = '')`
	args := []any{rule}
	if agent != "" {
		q += ` AND agent = ?`
		args = append(args, agent)
	}
	return q, args
}

// AcknowledgeRuleHost marks every UNacknowledged flag of `rule` whose
// evidence cites `host` (of `agent` when set) as acted-upon. Called when the operator mutes a
// rule+host pair: the mute suppresses future flags AND the existing ones
// leave the critical list — otherwise "ignore" looks like it did nothing.
// Idempotent; returns the number of flags newly acknowledged.
func (s *Store) AcknowledgeRuleHost(rule, host, agent string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	q, args := ackRuleHostQuery(rule, agent)
	rows, err := s.db.Query(q, args...)
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
		// Structured connection targets are authoritative; display wording
		// must not determine whether an operator's destination mute applies.
		h := item.Label
		if item.Kind != "connect" || h == "" {
			line := item.String()
			idx := strings.Index(line, "connected to ")
			if idx < 0 {
				continue
			}
			h = line[idx+len("connected to "):]
			if at := strings.Index(h, " at "); at >= 0 {
				h = h[:at]
			}
		}
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
	if n > 0 {
		s.syncLegacyReviewsLocked([]string{id})
	}
	return n > 0
}

// AcknowledgeFlags marks every id acted-upon in one transaction and returns
// how many rows it touched (a re-ack counts; an unknown id does not). Any
// error rolls the batch back and returns 0.
func (s *Store) AcknowledgeFlags(ids []string) int {
	return s.AcknowledgeFlagsReason(ids, "")
}

// AcknowledgeFlagsReason is AcknowledgeFlags recording why: the daemon's own
// acknowledgements carry a reason, the operator's carry none.
func (s *Store) AcknowledgeFlagsReason(ids []string, reason string) int {
	if len(ids) == 0 {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		log.Printf("store: acknowledge flags begin: %v", err)
		return 0
	}
	stmt, err := tx.Prepare(`UPDATE flags SET acknowledged = ?, ack_reason = ? WHERE id = ?`)
	if err != nil {
		_ = tx.Rollback()
		log.Printf("store: acknowledge flags prepare: %v", err)
		return 0
	}
	defer stmt.Close()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	n := 0
	for _, id := range ids {
		res, err := stmt.Exec(now, reason, id)
		if err != nil {
			_ = tx.Rollback()
			log.Printf("store: acknowledge flags error: %v", err)
			return 0
		}
		k, _ := res.RowsAffected()
		n += int(k)
	}
	if err := tx.Commit(); err != nil {
		log.Printf("store: acknowledge flags commit: %v", err)
		return 0
	}
	s.syncLegacyReviewsLocked(ids)
	return n
}

// ReattributeFlags relabels pid's "untagged:" flags stamped at or after since
// to agent, once the tagger has caught up with the process. Returns how many
// rows changed.
func (s *Store) ReattributeFlags(pid int32, agent string, since time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(reattributeFlagsSQL, agent, pid, since.UTC().Format(time.RFC3339Nano))
	if err != nil {
		log.Printf("store: reattribute flags error: %v", err)
		return 0
	}
	n, _ := res.RowsAffected()
	return int(n)
}

// decodeFlagProcess reads the stored process snapshot; nil when absent or
// unreadable.
func decodeFlagProcess(raw string) *model.FlagProcess {
	if raw == "" {
		return nil
	}
	var p model.FlagProcess
	if json.Unmarshal([]byte(raw), &p) != nil || p.Name == "" {
		return nil
	}
	return &p
}

func setFlagRepeats(fl *model.Flag, repeats sql.NullInt64, lastSeen sql.NullString) {
	fl.Repeats = int(repeats.Int64)
	if t, err := time.Parse(time.RFC3339Nano, lastSeen.String); err == nil {
		fl.LastSeen = &t
	}
}

// BumpFlagRepeat folds one more occurrence into flag id: repeats + 1 and
// last_seen = at when at is newer. False when no such flag is stored.
func (s *Store) BumpFlagRepeat(id string, at time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(
		`UPDATE flags SET repeats = COALESCE(repeats, 0) + 1,
		 last_seen = CASE WHEN last_seen IS NULL OR datetime(last_seen) < datetime(?) THEN ? ELSE last_seen END
		 WHERE id = ?`,
		at.UTC().Format(time.RFC3339Nano), at.UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		log.Printf("store: flag repeat %s: %v", id, err)
		return false
	}
	n, _ := res.RowsAffected()
	if n == 1 {
		if f, ok := s.getFlagLocked(id); ok && f.Rule == "sensitive-read-then-connect" {
			_, reviewErr := s.observeFindingReviewLocked(f, model.AssessFinding(f))
			s.noteWrite("finding reviews", reviewErr)
		}
	}
	return n == 1
}

func (s *Store) GetFlag(id string) (model.Flag, bool) {
	fl, found, _ := s.GetFlagResult(id)
	return fl, found
}

// GetFlagResult distinguishes a missing row from an unavailable or malformed
// detail, using the same checked decoder as flag history.
func (s *Store) GetFlagResult(id string) (model.Flag, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getFlagResultLocked(id)
}

func (s *Store) getFlagLocked(id string) (model.Flag, bool) {
	fl, found, _ := s.getFlagResultLocked(id)
	return fl, found
}

const flagSelect = `SELECT id, rule, severity, ts, pid, agent, session_id, workspace, evidence, acknowledged, ack_reason, process, repeats, last_seen FROM flags`

func (s *Store) getFlagResultLocked(id string) (flag model.Flag, found bool, readErr error) {
	defer func() { s.noteRead("flag detail", readErr) }()
	rows, err := s.db.Query(flagSelect+" WHERE id = ?", id)
	if err != nil {
		return model.Flag{}, false, err
	}
	flags, err := scanFlagsResult(rows)
	if err != nil {
		return model.Flag{}, false, err
	}
	if len(flags) == 0 {
		return model.Flag{}, false, nil
	}
	return flags[0], true, nil
}

// GetFlagWithAdvisor is GetFlag with its advisor verdict joined — the shape
// a flag delta publishes (wire.go), so a verdict that lands after the flag
// itself can be re-pushed with the same fields the popover already renders.
func (s *Store) GetFlagWithAdvisor(id string) (model.Flag, bool) {
	fl, ok := s.GetFlag(id)
	if !ok {
		return fl, false
	}
	flags := []model.Flag{fl}
	_ = s.AttachFindingReviewIDs(flags)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attachAdvisorLocked(flags)
	return flags[0], true
}

// flagQuery builds QueryFlags' statement. Its ORDER BY matches idx_flags_time,
// so a LIMIT walks the index instead of sorting every row.
func flagQuery(f FlagFilter) (string, []any) {
	q := flagSelect + " WHERE 1=1"
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
	args = append(args, flagLimit(f.Limit))
	return q, args
}

func (s *Store) QueryFlags(f FlagFilter) []model.Flag {
	flags, _ := s.QueryFlagsResult(f)
	return flags
}

// QueryFlagsResult never returns partial flags after a query, decode or
// cursor error. Nullable optional fields in older schemas remain valid.
func (s *Store) QueryFlagsResult(f FlagFilter) (out []model.Flag, readErr error) {
	defer func() { s.noteRead("flags", readErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()

	q, args := flagQuery(f)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	flags, err := scanFlagsResult(rows)
	if err != nil {
		return nil, err
	}
	s.attachAdvisorLocked(flags)
	return flags, nil
}

func scanFlagsResult(rows *sql.Rows) ([]model.Flag, error) {
	defer rows.Close()

	flags := []model.Flag{}
	for rows.Next() {
		var fl model.Flag
		var tsStr string
		var rule, agent, evStr, sessionID, workspace sql.NullString
		var ack, ackReason, proc, lastSeen sql.NullString
		var repeats sql.NullInt64
		if err := rows.Scan(&fl.ID, &rule, &fl.Severity, &tsStr, &fl.PID, &agent, &sessionID, &workspace, &evStr, &ack, &ackReason, &proc, &repeats, &lastSeen); err != nil {
			return nil, err
		}
		var err error
		fl.TS, err = time.Parse(time.RFC3339Nano, tsStr)
		if err != nil {
			return nil, fmt.Errorf("invalid flag timestamp: %w", err)
		}
		if lastSeen.String != "" {
			ts, err := time.Parse(time.RFC3339Nano, lastSeen.String)
			if err != nil {
				return nil, fmt.Errorf("invalid flag repeat timestamp: %w", err)
			}
			fl.LastSeen = &ts
		}
		if evStr.String != "" {
			if err := json.Unmarshal([]byte(evStr.String), &fl.Evidence); err != nil {
				return nil, fmt.Errorf("invalid flag evidence: %w", err)
			}
		}
		if proc.String != "" {
			var p model.FlagProcess
			if err := json.Unmarshal([]byte(proc.String), &p); err != nil {
				return nil, fmt.Errorf("invalid flag process: %w", err)
			}
			if p.Name != "" {
				fl.Process = &p
			}
		}
		fl.Rule, fl.Agent = rule.String, agent.String
		fl.Repeats = int(repeats.Int64)
		fl.SessionID, fl.Workspace = sessionID.String, workspace.String
		fl.Acknowledged, fl.AckReason = ack.String != "", ackReason.String
		flags = append(flags, fl)
	}
	// A mid-cursor error must not be served as a complete history.
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return flags, nil
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
// flag evidence names one): counts from the store, the host's identity from
// the CIDR/PTR cache (no network), and every agent the operator already
// allowed the host for.
func (s *Store) TrendFor(rule, host string) model.TrendContext {
	tc, allow := s.trendCounts(rule, host)
	if host == "" {
		return tc
	}
	id := hostid.IdentifyCached(host)
	tc.HostOrg = id.Org
	if !strings.EqualFold(id.Name, host) {
		tc.HostName = id.Name
	}
	if allow != nil {
		for agent, hosts := range allow() {
			for _, h := range hosts {
				if hostid.HostMatches(host, h) {
					tc.AllowedFor = append(tc.AllowedFor, agent)
					break
				}
			}
		}
		sort.Strings(tc.AllowedFor)
	}
	return tc
}

// trendCounts reads the rule/host counts under the lock and returns the
// allowlist source so TrendFor calls it without holding mu.
func (s *Store) trendCounts(rule, host string) (model.TrendContext, func() map[string][]string) {
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
		err := s.db.QueryRow(hostFirstSeenSQL, host).Scan(&first)
		if err == nil && first.Valid && first.String != "" {
			tc.HostKnown = true
			tc.HostFirstSeen = first.String
		}
	}
	return tc, s.allowlist
}

// PutAdvisorVerdict stores (or replaces) the local advisor's verdict for a
// flag or incident. Advisory metadata only — nothing reads it back into an
// enforcement decision.
func (s *Store) PutAdvisorVerdict(subjectID, kind string, v model.AdvisorVerdict) (writeErr error) {
	defer func() { s.noteWrite("advisor verdicts", writeErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(
		`INSERT OR REPLACE INTO advisor_verdicts
		 (subject_id, kind, assessment, confidence, rationale, suggested_action, model, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		subjectID, kind, v.Assessment, v.Confidence, v.Rationale, v.SuggestedAction, v.Model,
		v.CreatedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("insert advisor verdict: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("advisor verdict rows affected: %w", err)
	}
	if inserted != 1 {
		return fmt.Errorf("advisor verdict insert affected %d rows", inserted)
	}
	return nil
}

// attachAdvisorLocked joins stored verdicts onto flags (caller holds mu).
func (s *Store) attachAdvisorLocked(flags []model.Flag) {
	if len(flags) == 0 {
		return
	}
	var readErr error
	for i := range flags {
		v, ok, err := s.advisorVerdictResultLocked(flags[i].ID, "flag")
		if readErr == nil {
			readErr = err
		}
		if ok {
			vv := v
			flags[i].Advisor = &vv
		}
	}
	s.noteRead(advisorReadKind("flag"), readErr)
}

// advisorVerdictLocked fetches one verdict (caller holds mu).
func (s *Store) advisorVerdictLocked(subjectID, kind string) (model.AdvisorVerdict, bool) {
	v, found, err := s.advisorVerdictResultLocked(subjectID, kind)
	s.noteRead(advisorReadKind(kind), err)
	return v, found
}

// Separate health by subject kind so an unrelated successful lookup cannot
// clear a failing flag or incident enrichment read.
func advisorReadKind(kind string) string {
	switch kind {
	case "flag", "incident", "guard", "worktree", "host", "egress", "project":
		return kind + " advisor verdicts"
	default:
		return "advisor verdicts"
	}
}

func (s *Store) advisorVerdictResultLocked(subjectID, kind string) (model.AdvisorVerdict, bool, error) {
	var v model.AdvisorVerdict
	var conf sql.NullFloat64
	var assessment, action, modelName, created sql.NullString
	var rationale string
	err := s.db.QueryRow(
		`SELECT assessment, confidence, rationale, suggested_action, model, created_at
		 FROM advisor_verdicts WHERE subject_id = ? AND kind = ?`, subjectID, kind,
	).Scan(&assessment, &conf, &rationale, &action, &modelName, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return model.AdvisorVerdict{}, false, nil
	}
	if err != nil {
		return model.AdvisorVerdict{}, false, err
	}
	if math.IsNaN(conf.Float64) || math.IsInf(conf.Float64, 0) {
		return model.AdvisorVerdict{}, false, fmt.Errorf("invalid advisor confidence")
	}
	if created.String != "" {
		v.CreatedAt, err = time.Parse(time.RFC3339Nano, created.String)
		if err != nil {
			return model.AdvisorVerdict{}, false, fmt.Errorf("invalid advisor timestamp: %w", err)
		}
	}
	v.Assessment = assessment.String
	if conf.Valid {
		v.Confidence = conf.Float64
	}
	v.Rationale = rationale
	v.SuggestedAction = action.String
	v.Model = modelName.String
	return v, true, nil
}

func (s *Store) RecentEvents(limit int) []event.Event {
	return s.QueryEvents(EventFilter{Limit: limit})
}

// eventQuery builds QueryEvents' statement. A host filter repeats the index's
// empty-host exclusion so it seeks idx_events_host.
func eventQuery(f EventFilter) (string, []any) {
	return eventRecordQuery(f, false, 0)
}

func eventRecordQuery(f EventFilter, withID bool, beforeID int64) (string, []any) {
	columns := `kind, ts, pid, exe_path, session_id, path, remote_host, remote_port, detail,
		tool, tool_status, duration_ms, model, tokens_in, tokens_out, cost_usd, call_id, provider`
	if withID {
		columns = "id, " + columns
	}
	q := "SELECT " + columns + " FROM events WHERE 1=1"
	var args []any
	if beforeID > 0 {
		q += " AND id < ?"
		args = append(args, beforeID)
	}
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
		q += " AND remote_host = ? AND remote_host != ''"
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
	return q, args
}

func (s *Store) QueryEvents(f EventFilter) []event.Event {
	rows, _ := s.QueryEventsResult(f)
	return rows
}

// QueryEventsResult distinguishes a successful empty history from failed or
// incomplete reads. Decode and cursor errors never return partial evidence.
func (s *Store) QueryEventsResult(f EventFilter) (out []event.Event, readErr error) {
	defer func() { s.noteRead("events", readErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()

	q, args := eventQuery(f)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	return scanEventsResult(rows)
}

func scanEventsResult(rows *sql.Rows) ([]event.Event, error) {
	defer rows.Close()

	events := []event.Event{}
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

// Both projections use one checked decoder. An optional leading destination
// reads the durable row ID without adding store identity to bus events.
func scanEvent(rows *sql.Rows, leading ...any) (event.Event, error) {
	var e event.Event
	var kindInt int
	var tsStr string
	var exePath, sessionID, path, remoteHost, detail sql.NullString
	var remotePort sql.NullInt64
	var tool, toolStatus, modelName, callID, provider sql.NullString
	var durMs, tokIn, tokOut sql.NullInt64
	var cost sql.NullFloat64
	destinations := append(leading, &kindInt, &tsStr, &e.PID, &exePath, &sessionID, &path, &remoteHost, &remotePort, &detail,
		&tool, &toolStatus, &durMs, &modelName, &tokIn, &tokOut, &cost, &callID, &provider)
	if err := rows.Scan(destinations...); err != nil {
		return event.Event{}, err
	}
	var err error
	e.TS, err = time.Parse(time.RFC3339Nano, tsStr)
	if err != nil {
		return event.Event{}, fmt.Errorf("invalid event timestamp: %w", err)
	}
	if math.IsNaN(cost.Float64) || math.IsInf(cost.Float64, 0) {
		return event.Event{}, fmt.Errorf("non-finite event cost")
	}
	e.Kind = event.Kind(kindInt)
	e.ExePath = exePath.String
	e.SessionID = sessionID.String
	e.Path = path.String
	e.RemoteHost = remoteHost.String
	e.RemotePort = int(remotePort.Int64)
	e.Detail = detail.String
	e.ToolName = tool.String
	e.ToolStatus = toolStatus.String
	e.DurationMs = durMs.Int64
	e.Model = modelName.String
	e.Provider = provider.String
	e.TokensIn = tokIn.Int64
	e.TokensOut = tokOut.Int64
	e.CostUSD = cost.Float64
	e.CallID = callID.String
	return e, nil
}

// maxFlagQuery bounds QueryFlags above normalizeLimit's 1000 so a pattern
// window reads a whole flag storm in one query.
const maxFlagQuery = 5000

func flagLimit(limit int) int {
	if limit > maxFlagQuery {
		return maxFlagQuery
	}
	if limit > 1000 {
		return limit
	}
	return normalizeLimit(limit)
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

// PutIncident creates a report and rejects existing identities without changing
// their evidence or operator bookkeeping. Retention pruning remains best-effort
// and does not invalidate a successful insertion.
func (s *Store) PutIncident(inc model.IncidentReport) (writeErr error) {
	defer func() {
		s.noteWrite("incidents", writeErr)
		if writeErr != nil {
			log.Printf("store: failed to persist incident %s: %v", inc.ID, writeErr)
		}
	}()
	s.mu.Lock()
	defer s.mu.Unlock()

	inc.Remediation = nil
	if inc.AggregateCount == 0 {
		inc.AggregateCount = 1
	}
	data, err := json.Marshal(inc)
	if err != nil {
		return fmt.Errorf("marshal incident: %w", err)
	}

	tsStr := inc.Timestamp.UTC().Format(time.RFC3339Nano)
	flagIDs, _ := json.Marshal([]string{inc.FlagID})
	result, err := s.db.Exec(
		`INSERT INTO incidents (id, flag_id, pid, risk, report_json, created_at, rule, session_id, subject, aggregate_count, last_flag_at, flag_ids, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')`,
		inc.ID, inc.FlagID, inc.PID, string(inc.Risk), string(data), tsStr,
		inc.Rule, inc.SessionID, inc.Subject, inc.AggregateCount, tsStr, string(flagIDs),
	)
	if err != nil {
		return fmt.Errorf("insert incident: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("incident rows affected: %w", err)
	}
	if inserted != 1 {
		return fmt.Errorf("incident insert affected %d rows", inserted)
	}

	// Retention: a flag storm inserts a full report_json per incident; cap the
	// table so the always-on daemon's DB stays bounded (events are already capped).
	// Order by the normalized instant, not raw text: local-offset stamps sort
	// wrong lexicographically across a DST change.
	_, _ = s.db.Exec(trimIncidentsSQL, maxIncidents)
	return nil
}

func (s *Store) GetIncident(id string) (report *model.IncidentReport, readErr error) {
	defer func() {
		if readErr == sql.ErrNoRows {
			s.noteRead("incidents", nil)
		} else {
			s.noteRead("incidents", readErr)
		}
	}()
	s.mu.Lock()
	defer s.mu.Unlock()

	var storedID, reportJSON string
	err := s.db.QueryRow(`SELECT id, report_json FROM incidents WHERE id = ?`, id).Scan(&storedID, &reportJSON)
	if err == sql.ErrNoRows {
		// Flag aliases include evidence aggregated after the initial report.
		// Resolve the report identity first so an alias cannot shadow it.
		err = s.db.QueryRow(`SELECT id, report_json FROM incidents
			WHERE flag_id = ? OR EXISTS (SELECT 1 FROM json_each(COALESCE(flag_ids,'[]')) WHERE value = ?)
			ORDER BY `+timestampOrderExpr("created_at")+` DESC, id DESC LIMIT 1`, id, id).Scan(&storedID, &reportJSON)
	}
	if err != nil {
		return nil, err
	}

	inc, err := decodeIncidentReport(storedID, reportJSON)
	if err != nil {
		return nil, err
	}
	if err := s.attachIncidentRemediationLocked(inc); err != nil {
		return nil, err
	}
	if v, ok := s.advisorVerdictLocked(inc.ID, "incident"); ok {
		inc.AdvisorNarrative = v.Rationale
	}
	return inc, nil
}

func decodeIncidentReport(id, reportJSON string) (*model.IncidentReport, error) {
	var inc *model.IncidentReport
	if err := json.Unmarshal([]byte(reportJSON), &inc); err != nil {
		return nil, err
	}
	if inc == nil || inc.ID == "" || inc.ID != id {
		return nil, fmt.Errorf("invalid incident report identity")
	}
	return inc, nil
}

// IncidentIDForFlag returns the incident a flag opened or was aggregated
// into (newest first).
func (s *Store) IncidentIDForFlag(flagID string) (string, bool) {
	id, found, _ := s.IncidentIDForFlagResult(flagID)
	return id, found
}

// FindOpenIncident returns the open (unresolved) incident matching the
// aggregation key — one incident per rule+session+subject; repeat flags
// become its evidence instead of minting duplicate reports.
func (s *Store) FindOpenIncident(rule, sessionID, subject string) (string, bool) {
	id, found, _ := s.FindOpenIncidentResult(rule, sessionID, subject)
	return id, found
}

// FindOpenIncidentResult distinguishes a missing aggregation target from an
// unavailable or invalid stored identity. Callers creating reports must use it.
func (s *Store) FindOpenIncidentResult(rule, sessionID, subject string) (id string, found bool, readErr error) {
	defer func() { s.noteRead("incident lookup", readErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.db.QueryRow(findOpenIncidentSQL, rule, sessionID, subject).Scan(&id)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if id == "" {
		return "", false, fmt.Errorf("invalid open incident identity")
	}
	return id, true, nil
}

// AggregateIntoIncident folds another flag into an existing incident: bumps
// the count, records the flag id as evidence, refreshes last_flag_at, and
// patches the served report_json so the UI reads current numbers. Returns
// the persisted report (for the incident delta) — false when the row is gone,
// its evidence cannot be decoded, or the update does not persist.
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
		if err != sql.ErrNoRows {
			s.noteWrite("incident aggregation", err)
		}
		return model.IncidentReport{}, false
	}
	var storedFlagIDs []*string
	if err := json.Unmarshal([]byte(flagIDsRaw), &storedFlagIDs); err != nil {
		s.noteWrite("incident aggregation", err)
		return model.IncidentReport{}, false
	}
	if storedFlagIDs == nil {
		s.noteWrite("incident aggregation", fmt.Errorf("null incident flag evidence"))
		return model.IncidentReport{}, false
	}
	flagIDs := make([]string, len(storedFlagIDs))
	for i, storedID := range storedFlagIDs {
		if storedID == nil {
			s.noteWrite("incident aggregation", fmt.Errorf("null incident flag identity"))
			return model.IncidentReport{}, false
		}
		flagIDs[i] = *storedID
	}
	inc, err := decodeIncidentReport(id, reportJSON)
	if err != nil {
		s.noteWrite("incident aggregation", err)
		return model.IncidentReport{}, false
	}
	if inc.FlagID != "" && !slices.Contains(flagIDs, inc.FlagID) {
		flagIDs = append(flagIDs, inc.FlagID)
	}
	for _, existing := range flagIDs {
		if existing == flagID {
			if err := s.attachIncidentRemediationLocked(inc); err != nil {
				s.noteRead("incidents", err)
				return model.IncidentReport{}, false
			}
			s.noteRead("incidents", nil)
			return *inc, true
		}
	}
	if inc.Rule == "proxy-secret-leak" {
		if inc.PayloadOutcomes == nil {
			// Historic reports do not establish any of their control outcomes.
			inc.PayloadOutcomes = &model.PayloadOutcomeSummary{Unknown: count}
		}
		var source model.Flag
		var evidence string
		err := s.db.QueryRow(`SELECT rule, evidence FROM flags WHERE id = ?`, flagID).Scan(&source.Rule, &evidence)
		if err != nil && err != sql.ErrNoRows {
			s.noteWrite("incident aggregation", err)
			return model.IncidentReport{}, false
		}
		if err == nil {
			if err := json.Unmarshal([]byte(evidence), &source.Evidence); err != nil {
				s.noteWrite("incident aggregation", err)
				return model.IncidentReport{}, false
			}
		}
		outcome := model.PayloadOutcomeForFinding(source)
		if outcome == nil {
			outcome = &model.PayloadOutcomeSummary{Unknown: 1}
		}
		inc.PayloadOutcomes.Blocked += outcome.Blocked
		inc.PayloadOutcomes.ObservedOnly += outcome.ObservedOnly
		inc.PayloadOutcomes.Unknown += outcome.Unknown
	}
	flagIDs = append(flagIDs, flagID)
	count++
	inc.AggregateCount = count
	t := ts.UTC()
	if inc.Timestamp.After(t) {
		t = inc.Timestamp.UTC()
	}
	if inc.LastFlagAt != nil && inc.LastFlagAt.After(t) {
		t = inc.LastFlagAt.UTC()
	}
	inc.LastFlagAt = &t
	tsStr := t.Format(time.RFC3339Nano)
	data, err := json.Marshal(inc)
	if err != nil {
		s.noteWrite("incident aggregation", err)
		return model.IncidentReport{}, false
	}
	reportJSON = string(data)
	idsJSON, _ := json.Marshal(flagIDs)
	result, err := s.db.Exec(`UPDATE incidents SET aggregate_count = ?, last_flag_at = ?, flag_ids = ?, report_json = ? WHERE id = ?`,
		count, tsStr, string(idsJSON), reportJSON, id)
	if err != nil {
		s.noteWrite("incident aggregation", err)
		return model.IncidentReport{}, false
	}
	updated, err := result.RowsAffected()
	if err != nil {
		s.noteWrite("incident aggregation", err)
		return model.IncidentReport{}, false
	}
	if updated != 1 {
		return model.IncidentReport{}, false
	}
	s.noteWrite("incident aggregation", nil)
	if err := s.attachIncidentRemediationLocked(inc); err != nil {
		s.noteRead("incidents", err)
		return model.IncidentReport{}, false
	}
	s.noteRead("incidents", nil)
	return *inc, true
}

func (s *Store) RecentIncidents(limit int) []model.IncidentReport {
	incidents, _ := s.RecentIncidentsResult(limit)
	return incidents
}

// RecentIncidentsResult returns no partial history after query, scan, report
// decode or cursor failure. Resolved reports remain outside the active set.
func (s *Store) RecentIncidentsResult(limit int) (out []model.IncidentReport, readErr error) {
	defer func() { s.noteRead("incidents", readErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()

	// Resolved incidents stay in the audit trail but leave the active set:
	// the operator dismissed them, so they must not keep rendering as
	// critical rows in the popover.
	rows, err := s.db.Query(recentIncidentsQuery, normalizeLimit(limit))
	if err != nil {
		return nil, err
	}
	list, err := scanIncidentsResult(rows)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if err := s.attachIncidentRemediationLocked(&list[i]); err != nil {
			return nil, err
		}
	}
	s.attachNarrativesLocked(list)
	return list, nil
}

// Include NULL status so an unreadable workflow cannot silently hide a report.
const recentIncidentsQuery = `SELECT id, report_json FROM incidents WHERE (status IS NULL OR status != 'resolved') ORDER BY datetime(created_at) DESC, created_at DESC LIMIT ?`

func scanIncidentsResult(rows *sql.Rows) ([]model.IncidentReport, error) {
	defer rows.Close()

	list := []model.IncidentReport{}
	for rows.Next() {
		var id, reportJSON string
		if err := rows.Scan(&id, &reportJSON); err != nil {
			return nil, err
		}
		inc, err := decodeIncidentReport(id, reportJSON)
		if err != nil {
			return nil, err
		}
		list = append(list, *inc)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return list, nil
}

// CriticalFlagsMissingAdvisor returns recent severity-3 flags that have no
// advisor verdict yet — the backfill set for when the advisor is enabled
// after flags already fired. Bounded by limit.
func (s *Store) CriticalFlagsMissingAdvisor(since time.Time, limit int) []model.Flag {
	flags, _ := s.CriticalFlagsMissingAdvisorResult(since, limit)
	return flags
}

// CriticalFlagsMissingAdvisorResult rejects failed reads without returning a
// partial backfill. Nullable legacy metadata is decoded like other flag reads.
func (s *Store) CriticalFlagsMissingAdvisorResult(since time.Time, limit int) (flags []model.Flag, readErr error) {
	defer func() { s.noteRead("advisor backfill", readErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	// Invalid dates must reach the decoder rather than disappear from the
	// time filter or fall beyond the limit behind valid rows.
	rows, err := s.db.Query(
		flagSelect+` WHERE severity >= 3
		 AND NOT EXISTS (SELECT 1 FROM advisor_verdicts v WHERE v.subject_id = flags.id AND v.kind = 'flag')
		 AND (datetime(ts) IS NULL OR datetime(ts) >= datetime(?))
		 ORDER BY datetime(ts) IS NULL DESC, datetime(ts) DESC, ts DESC LIMIT ?`,
		since.UTC().Format(time.RFC3339Nano), normalizeLimit(limit),
	)
	if err != nil {
		return nil, err
	}
	return scanFlagsResult(rows)
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
			out[p] = ts.UTC().Format(time.RFC3339Nano)
		}
	}
	return out
}

// AdvisorVerdictFor fetches one stored verdict (public read; absent = false).
func (s *Store) AdvisorVerdictFor(subjectID, kind string) (model.AdvisorVerdict, bool) {
	v, found, _ := s.AdvisorVerdictResultFor(subjectID, kind)
	return v, found
}

// AdvisorVerdictResultFor distinguishes absent advice from unavailable or
// malformed stored advice without returning a partial verdict.
func (s *Store) AdvisorVerdictResultFor(subjectID, kind string) (v model.AdvisorVerdict, found bool, readErr error) {
	defer func() { s.noteRead(advisorReadKind(kind), readErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.advisorVerdictResultLocked(subjectID, kind)
}

// attachNarrativesLocked joins advisor narratives onto incidents (caller
// holds mu).
func (s *Store) attachNarrativesLocked(list []model.IncidentReport) {
	if len(list) == 0 {
		return
	}
	var readErr error
	for i := range list {
		v, ok, err := s.advisorVerdictResultLocked(list[i].ID, "incident")
		if readErr == nil {
			readErr = err
		}
		if ok {
			list[i].AdvisorNarrative = v.Rationale
		}
	}
	s.noteRead(advisorReadKind("incident"), readErr)
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
	s.noteWrite("operator audit", err)
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

func (s *Store) PutResourceEpisode(episode resource.Episode) (writeErr error) {
	defer func() { s.noteWrite("resource episodes", writeErr) }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	episode.ActivityStatus = "settling"
	// The session id only scopes the activity read here (its harness trace
	// rows carry no pid); the id stored below is looked up again with the
	// insert, on one side of a rekey.
	probe := episode
	probe.SessionID = ""
	if episode.Session.Kind != "infra" {
		s.mu.Lock()
		probe.SessionID = s.sessionIDForRootLocked(episode.Session.RootPID, episode.Session.RootStartedAt)
		s.mu.Unlock()
	}
	enriched, enrichErr := s.attachResourceEpisodeActivity(ctx, probe)
	episode = enriched
	// RekeySession holds this same mutex through its transaction. Keep the
	// exact identity lookup, JSON payload, and insert on one side of a rekey.
	s.mu.Lock()
	defer s.mu.Unlock()
	// The caller's optional ID is not trusted. Only a unique, exact root
	// process identity can attach an agent episode to a durable session.
	episode.SessionID = ""
	if episode.Session.Kind != "infra" {
		episode.SessionID = s.sessionIDForRootLocked(episode.Session.RootPID, episode.Session.RootStartedAt)
	}
	if s.resourceEpisodeAfterLookup != nil {
		s.resourceEpisodeAfterLookup()
	}
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
	var sessionID any
	if episode.SessionID != "" {
		sessionID = episode.SessionID
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO resource_episodes (captured_at, severity, session_key, session_id, episode_json) VALUES (?, ?, ?, ?, ?)`,
		episode.CapturedAt.UTC().Format(time.RFC3339Nano), episode.Severity, episode.Session.Key, sessionID, string(payload),
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
	activityKeys := make(map[string]int, len(activities))
	for i, activity := range activities {
		activityKeys[resourceActivityKey(activity)] = i
	}
	// A record read again replaces its earlier copy only when it carries a
	// Ref (completed in place); any other repeat is the same fact.
	appendActivity := func(activity resource.EpisodeActivity) {
		key := resourceActivityKey(activity)
		if i, exists := activityKeys[key]; exists {
			if activity.Ref != "" {
				activities[i] = activity
			}
			return
		}
		activityKeys[key] = len(activities)
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
	if end.IsZero() || (len(pids) == 0 && episode.SessionID == "") {
		return resource.AttachEpisodeActivity(episode, activities), nil
	}

	// Two reads: the family's OS telemetry by pid, and the session's own rows
	// by id. Tool calls, model calls and turns carry no pid, and a child that
	// exited before capture is in the session but not in the family list.
	if len(pids) > 0 {
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(pids)), ",")
		args := make([]any, 0, len(pids)+2)
		for _, pid := range pids {
			args = append(args, pid)
		}
		args = append(args, start.UTC().Format(time.RFC3339Nano), end.UTC().Format(time.RFC3339Nano))
		err := s.scanResourceActivity(ctx, `SELECT `+resourceActivityColumns+`
			FROM events WHERE pid IN (`+placeholders+`)
			AND datetime(ts) >= datetime(?) AND datetime(ts) <= datetime(?)
			ORDER BY datetime(ts) DESC, id DESC`, args, func(e event.Event) {
			process := processes[e.PID]
			if e.TS.Before(start) || e.TS.After(end) || (!process.StartedAt.IsZero() && e.TS.Before(process.StartedAt)) {
				return
			}
			appendActivity(resourceActivity(e, process.Name, end))
		})
		if err != nil {
			return resource.AttachEpisodeActivity(episode, activities), err
		}
	}
	if episode.SessionID != "" {
		at := memoryTimestampExpr("ts")
		err := s.scanResourceActivity(ctx, `SELECT `+resourceActivityColumns+`
			FROM events WHERE session_id = ? AND strftime('%s', ts) IS NOT NULL
			AND `+at+` >= ? AND `+at+` <= ?
			ORDER BY `+at+` DESC, id DESC`,
			[]any{episode.SessionID, start.UnixNano(), end.UnixNano()}, func(e event.Event) {
				name := episode.Session.Name
				if process, ok := processes[e.PID]; ok {
					name = process.Name
				}
				appendActivity(resourceActivity(e, name, end))
			})
		if err != nil {
			return resource.AttachEpisodeActivity(episode, activities), err
		}
	}
	return resource.AttachEpisodeActivity(episode, activities), nil
}

const resourceActivityColumns = `kind, ts, pid, COALESCE(exe_path,''), COALESCE(path,''), COALESCE(remote_host,''),
	COALESCE(remote_port,0), COALESCE(detail,''), COALESCE(tool,''), COALESCE(tool_status,''),
	COALESCE(duration_ms,0), COALESCE(model,''), COALESCE(tokens_in,0), COALESCE(tokens_out,0), COALESCE(call_id,'')`

// scanResourceActivity runs one activity read and hands each decoded row to
// visit.
func (s *Store) scanResourceActivity(ctx context.Context, query string, args []any, visit func(event.Event)) error {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("query resource episode activity: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var e event.Event
		var kind int
		var ts string
		if err := rows.Scan(&kind, &ts, &e.PID, &e.ExePath, &e.Path, &e.RemoteHost, &e.RemotePort, &e.Detail,
			&e.ToolName, &e.ToolStatus, &e.DurationMs, &e.Model, &e.TokensIn, &e.TokensOut, &e.CallID); err != nil {
			continue
		}
		e.Kind = event.Kind(kind)
		if e.TS, err = time.Parse(time.RFC3339Nano, ts); err != nil {
			continue
		}
		visit(e)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read resource episode activity: %w", err)
	}
	return nil
}

// resourceActivity converts one stored row. A tool call that returned ends
// after its duration; one still running when the episode was captured spans
// to the capture, until a later read finds it completed.
func resourceActivity(e event.Event, process string, captured time.Time) resource.EpisodeActivity {
	activity := resource.EpisodeActivity{
		At: e.TS, Kind: resourceActivityKind(e.Kind), PID: e.PID, Process: process,
		Summary: resourceActivitySummary(e),
	}
	if e.Kind == event.KindToolCall {
		switch {
		case e.DurationMs > 0:
			activity.EndedAt = e.TS.Add(time.Duration(e.DurationMs) * time.Millisecond)
		case e.ToolStatus == "running" && captured.After(e.TS):
			activity.EndedAt = captured
		}
	}
	// Both rows are updated in place under their call id: a tool call gains
	// its status and duration, a model call its final token counts.
	if e.CallID != "" && (e.Kind == event.KindToolCall || e.Kind == event.KindModelCall) {
		activity.Ref = "call:" + e.CallID
	}
	return activity
}

// resourceActivityKey identifies one activity across re-enrichments: a Ref'd
// record by its ref (its summary and end change when it completes), anything
// else by its content.
func resourceActivityKey(activity resource.EpisodeActivity) string {
	if activity.Ref != "" {
		return activity.Kind + "|" + activity.Ref
	}
	return fmt.Sprintf("%d|%s|%d|%s", activity.At.UnixNano(), activity.Kind, activity.PID, activity.Summary)
}

func resourceActivityKind(kind event.Kind) string {
	switch kind {
	case event.KindExec:
		return "process"
	case event.KindPluginAction, event.KindToolCall:
		return "tool"
	case event.KindModelCall:
		return "model"
	case event.KindTurn:
		return "turn"
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
	case event.KindToolCall:
		summary = resourceToolCallSummary(e)
	case event.KindModelCall:
		summary = "model call"
		if e.Model != "" {
			summary = e.Model + " call"
		}
		if e.TokensIn > 0 || e.TokensOut > 0 {
			summary += fmt.Sprintf(": %d tokens in, %d out", e.TokensIn, e.TokensOut)
		}
	case event.KindTurn:
		summary = "new turn"
	default:
		summary = e.Kind.String()
	}
	if strings.TrimSpace(summary) == "" {
		summary = e.Kind.String()
	}
	return truncateResourceActivity(summary, 160)
}

// resourceToolCallSummary names the tool and how its call ended; never its
// input or output.
func resourceToolCallSummary(e event.Event) string {
	tool := e.ToolName
	if tool == "" {
		tool = "tool"
	}
	took := ""
	if e.DurationMs > 0 {
		took = " after " + (time.Duration(e.DurationMs) * time.Millisecond).Round(time.Millisecond).String()
	}
	switch e.ToolStatus {
	case "running", "":
		return tool + " was running"
	case "ok":
		return tool + " returned" + took
	case "error":
		return tool + " failed" + took
	default: // a trace without result pairing ("unknown")
		return tool + " called"
	}
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
		if s.episodeSettled(enriched.CapturedAt) {
			enriched.ActivityStatus = "complete"
		}
		persisted := enriched
		persisted.ID = 0
		payload, err := json.Marshal(persisted)
		if err != nil {
			s.noteWrite("resource episode enrichment", err)
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
			s.noteWrite("resource episode enrichment", err)
			log.Printf("store: refresh resource episode %d: %v", id, err)
			return persistedFallback
		}
		if updated, _ := result.RowsAffected(); updated == 1 {
			s.noteWrite("resource episode enrichment", nil)
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

// mergeResourceActivities adds additional to existing; a Ref'd record in
// additional is the fresher read and replaces its existing copy.
func mergeResourceActivities(existing, additional []resource.EpisodeActivity) []resource.EpisodeActivity {
	merged := append([]resource.EpisodeActivity(nil), existing...)
	seen := make(map[string]int, len(merged))
	for i, activity := range merged {
		seen[resourceActivityKey(activity)] = i
	}
	for _, activity := range additional {
		key := resourceActivityKey(activity)
		if i, ok := seen[key]; ok {
			if activity.Ref != "" {
				merged[i] = activity
			}
			continue
		}
		seen[key] = len(merged)
		merged = append(merged, activity)
	}
	return merged
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.flagMirror != nil {
		s.flagMirror.close()
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
func (s *Store) PutGuardPathAllow(g GuardPathAllow) error {
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
	return err
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
	_, updated, err := s.SetIncidentStatusResult(id, status, note)
	return updated, err
}

// ErrInvalidIncidentStatus distinguishes invalid input from storage failure.
var ErrInvalidIncidentStatus = errors.New("invalid incident status")

// SetIncidentStatusResult returns the workflow read in the same transaction as
// the update. An unreadable result or failed commit leaves no successful update.
func (s *Store) SetIncidentStatusResult(id, status, note string) (workflow IncidentWorkflow, updated bool, writeErr error) {
	var query string
	var args []any
	switch status {
	case "acknowledged":
		query = `UPDATE incidents SET status='acknowledged',
			acknowledged_at=COALESCE(acknowledged_at, ?)
			WHERE id = ?`
		args = []any{time.Now().UTC().Format(time.RFC3339Nano)}
	case "resolved":
		query = `UPDATE incidents SET status='resolved', resolved_at=?, resolution_note=?
			WHERE id = ?`
		args = []any{time.Now().UTC().Format(time.RFC3339Nano), note}
	case "open":
		query = `UPDATE incidents SET status='open', acknowledged_at=NULL, resolved_at=NULL, resolution_note=NULL
			WHERE id = ?`
	default:
		return IncidentWorkflow{}, false, fmt.Errorf("%w %q (open|acknowledged|resolved)", ErrInvalidIncidentStatus, status)
	}
	defer func() { s.noteWrite("incident workflows", writeErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return IncidentWorkflow{}, false, err
	}
	defer tx.Rollback()
	storedID, err := resolveIncidentWorkflowID(tx, id)
	if err == sql.ErrNoRows {
		s.noteRead("incident workflows", nil)
		return IncidentWorkflow{}, false, nil
	}
	if err != nil {
		s.noteRead("incident workflows", err)
		return IncidentWorkflow{}, false, err
	}
	res, err := tx.Exec(query, append(args, storedID)...)
	if err != nil {
		return IncidentWorkflow{}, false, err
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return IncidentWorkflow{}, false, err
	}
	if changed == 0 {
		return IncidentWorkflow{}, false, nil
	}
	wf, err := scanIncidentWorkflow(tx.QueryRow(
		`SELECT status, acknowledged_at, resolved_at, resolution_note FROM incidents WHERE id = ?`, storedID))
	s.noteRead("incident workflows", err)
	if err != nil {
		return IncidentWorkflow{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return IncidentWorkflow{}, false, err
	}
	return wf, true, nil
}

// IncidentStatus returns the workflow state for one incident.
func (s *Store) IncidentStatus(id string) (IncidentWorkflow, bool) {
	wf, found, _ := s.IncidentStatusResult(id)
	return wf, found
}

// IncidentStatusResult distinguishes a missing row from an unavailable or
// malformed workflow. Missing rows are healthy reads, not storage failures.
func (s *Store) IncidentStatusResult(id string) (workflow IncidentWorkflow, found bool, readErr error) {
	defer func() { s.noteRead("incident workflows", readErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()

	storedID, err := resolveIncidentWorkflowID(s.db, id)
	if err == sql.ErrNoRows {
		return IncidentWorkflow{Status: "unknown"}, false, nil
	}
	if err != nil {
		return IncidentWorkflow{Status: "unknown"}, false, err
	}
	wf, err := scanIncidentWorkflow(s.db.QueryRow(
		`SELECT status, acknowledged_at, resolved_at, resolution_note FROM incidents WHERE id = ?`, storedID))
	if err != nil {
		return IncidentWorkflow{Status: "unknown"}, false, err
	}
	return wf, true, nil
}

// resolveIncidentWorkflowID follows incident detail identity precedence: an
// exact report ID wins; otherwise the newest report linked to the flag wins.
// Updates use their transaction here so selection and mutation stay together.
func resolveIncidentWorkflowID(q interface{ QueryRow(string, ...any) *sql.Row }, id string) (string, error) {
	var storedID string
	err := q.QueryRow(`SELECT id FROM incidents WHERE id = ?`, id).Scan(&storedID)
	if err == sql.ErrNoRows {
		err = q.QueryRow(`SELECT id FROM incidents
			WHERE flag_id = ? OR EXISTS (SELECT 1 FROM json_each(COALESCE(flag_ids,'[]')) WHERE value = ?)
			ORDER BY `+timestampOrderExpr("created_at")+` DESC, id DESC LIMIT 1`, id, id).Scan(&storedID)
	}
	return storedID, err
}

func scanIncidentWorkflow(row *sql.Row) (IncidentWorkflow, error) {
	var wf IncidentWorkflow
	var ack, res, note sql.NullString
	if err := row.Scan(&wf.Status, &ack, &res, &note); err != nil {
		return IncidentWorkflow{}, err
	}
	switch wf.Status {
	case "open", "acknowledged", "resolved":
	default:
		return IncidentWorkflow{}, fmt.Errorf("invalid incident workflow status")
	}
	wf.AcknowledgedAt = ack.String
	wf.ResolvedAt = res.String
	wf.ResolutionNote = note.String
	return wf, nil
}

// ReclassifyReadConnectSeverity changes only unresolved weak correlations.
// It retains every finding, evidence row and operator disposition.
func (s *Store) ReclassifyReadConnectSeverity(ids []string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, id := range ids {
		res, err := s.db.Exec(`UPDATE flags SET severity=2 WHERE id=? AND rule='sensitive-read-then-connect' AND severity=3 AND acknowledged IS NULL`, id)
		if err != nil {
			log.Printf("store: reclassify severity: %v", err)
			continue
		}
		count, _ := res.RowsAffected()
		n += int(count)
	}
	return n
}
