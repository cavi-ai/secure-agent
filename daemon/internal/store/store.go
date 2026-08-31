package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

type Store struct {
	mu          sync.Mutex
	db          *sql.DB
	jsonlFile   *os.File
	insertCount uint64
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
	if dbPath != "" {
		if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
			return nil, fmt.Errorf("failed to create db dir: %w", err)
		}
	}
	if jsonlPath != "" {
		if err := os.MkdirAll(filepath.Dir(jsonlPath), 0o755); err != nil {
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
			evidence TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			kind INT,
			ts TEXT,
			pid INT,
			exe_path TEXT,
			path TEXT,
			remote_host TEXT,
			remote_port INT,
			detail TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS incidents (
			id TEXT PRIMARY KEY,
			flag_id TEXT,
			pid INT,
			risk TEXT,
			report_json TEXT,
			created_at TEXT
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
	}

	for _, q := range createQueries {
		if _, err := db.Exec(q); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to init db schema: %w", err)
		}
	}

	var jsonl *os.File
	if jsonlPath != "" {
		f, err := os.OpenFile(jsonlPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			log.Printf("store: warning: failed to open jsonl path %s: %v", jsonlPath, err)
		} else {
			jsonl = f
		}
	}

	return &Store{
		db:        db,
		jsonlFile: jsonl,
	}, nil
}

func (s *Store) PutFlag(fl model.Flag) {
	s.mu.Lock()
	defer s.mu.Unlock()

	evJSON, _ := json.Marshal(fl.Evidence)
	tsStr := fl.TS.Format(time.RFC3339Nano)

	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO flags (id, rule, severity, ts, pid, agent, evidence) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		fl.ID, fl.Rule, fl.Severity, tsStr, fl.PID, fl.Agent, string(evJSON),
	)
	if err != nil {
		log.Printf("store: failed to insert flag %s: %v", fl.ID, err)
	}

	if s.jsonlFile != nil {
		data, err := json.Marshal(fl)
		if err == nil {
			s.jsonlFile.Write(append(data, '\n'))
		}
	}
}

func (s *Store) PutEvent(e event.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tsStr := e.TS.Format(time.RFC3339Nano)
	_, err := s.db.Exec(
		`INSERT INTO events (kind, ts, pid, exe_path, path, remote_host, remote_port, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		int(e.Kind), tsStr, e.PID, e.ExePath, e.Path, e.RemoteHost, e.RemotePort, e.Detail,
	)
	if err != nil {
		log.Printf("store: failed to insert event: %v", err)
	}

	s.insertCount++
	if s.insertCount%1000 == 0 {
		s.pruneEventsLocked(10000)
	}
}

func (s *Store) PruneEvents(maxKeep int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneEventsLocked(maxKeep)
}

func (s *Store) pruneEventsLocked(maxKeep int) {
	if maxKeep <= 0 {
		maxKeep = 10000
	}
	_, _ = s.db.Exec(`DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)`, maxKeep)
}

// FlagFilter narrows a flag history query. A zero value returns the most recent
// flags — RecentFlags is exactly that. Since is any RFC3339 timestamp (any
// offset); it is compared with SQLite's datetime() so stored local-offset
// stamps and a UTC bound normalize to the same instant.
type FlagFilter struct {
	Agent       string // exact match; empty = any
	Rule        string // exact match; empty = any
	MinSeverity int    // severity >= this; 0 = any
	Since       string // ts >= this; empty = any
	Limit       int    // 0 = 50
}

// EventFilter narrows an event history query. Kind is a pointer because kind 0
// (KindFileOpen) is a valid filter value distinct from "not set".
type EventFilter struct {
	Kind  *int   // exact kind; nil = any
	PID   int32  // exact pid; 0 = any
	Since string // ts >= this; empty = any
	Limit int    // 0 = 50
}

func (s *Store) RecentFlags(limit int) []model.Flag {
	return s.QueryFlags(FlagFilter{Limit: limit})
}

func (s *Store) QueryFlags(f FlagFilter) []model.Flag {
	s.mu.Lock()
	defer s.mu.Unlock()

	q := `SELECT id, rule, severity, ts, pid, agent, evidence FROM flags WHERE 1=1`
	var args []any
	if f.Agent != "" {
		q += " AND agent = ?"
		args = append(args, f.Agent)
	}
	if f.Rule != "" {
		q += " AND rule = ?"
		args = append(args, f.Rule)
	}
	if f.MinSeverity > 0 {
		q += " AND severity >= ?"
		args = append(args, f.MinSeverity)
	}
	if f.Since != "" {
		q += " AND datetime(ts) >= datetime(?)"
		args = append(args, f.Since)
	}
	q += " ORDER BY ts DESC LIMIT ?"
	args = append(args, normalizeLimit(f.Limit))

	rows, err := s.db.Query(q, args...)
	if err != nil {
		log.Printf("store: query flags error: %v", err)
		return nil
	}
	defer rows.Close()

	var flags []model.Flag
	for rows.Next() {
		var fl model.Flag
		var tsStr, evStr string
		if err := rows.Scan(&fl.ID, &fl.Rule, &fl.Severity, &tsStr, &fl.PID, &fl.Agent, &evStr); err == nil {
			fl.TS, _ = time.Parse(time.RFC3339Nano, tsStr)
			_ = json.Unmarshal([]byte(evStr), &fl.Evidence)
			flags = append(flags, fl)
		}
	}
	return flags
}

func (s *Store) RecentEvents(limit int) []event.Event {
	return s.QueryEvents(EventFilter{Limit: limit})
}

func (s *Store) QueryEvents(f EventFilter) []event.Event {
	s.mu.Lock()
	defer s.mu.Unlock()

	q := `SELECT kind, ts, pid, exe_path, path, remote_host, remote_port, detail FROM events WHERE 1=1`
	var args []any
	if f.Kind != nil {
		q += " AND kind = ?"
		args = append(args, *f.Kind)
	}
	if f.PID != 0 {
		q += " AND pid = ?"
		args = append(args, f.PID)
	}
	if f.Since != "" {
		q += " AND datetime(ts) >= datetime(?)"
		args = append(args, f.Since)
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, normalizeLimit(f.Limit))

	rows, err := s.db.Query(q, args...)
	if err != nil {
		log.Printf("store: query events error: %v", err)
		return nil
	}
	defer rows.Close()

	var events []event.Event
	for rows.Next() {
		var e event.Event
		var kindInt int
		var tsStr string
		if err := rows.Scan(&kindInt, &tsStr, &e.PID, &e.ExePath, &e.Path, &e.RemoteHost, &e.RemotePort, &e.Detail); err == nil {
			e.Kind = event.Kind(kindInt)
			e.TS, _ = time.Parse(time.RFC3339Nano, tsStr)
			events = append(events, e)
		}
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

func (s *Store) PutIncident(inc model.IncidentReport) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(inc)
	if err != nil {
		log.Printf("store: failed to marshal incident %s: %v", inc.ID, err)
		return
	}

	tsStr := inc.Timestamp.Format(time.RFC3339Nano)
	_, err = s.db.Exec(
		`INSERT OR REPLACE INTO incidents (id, flag_id, pid, risk, report_json, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		inc.ID, inc.FlagID, inc.PID, string(inc.Risk), string(data), tsStr,
	)
	if err != nil {
		log.Printf("store: failed to insert incident %s: %v", inc.ID, err)
	}
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
	return &inc, nil
}

func (s *Store) RecentIncidents(limit int) []model.IncidentReport {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`SELECT report_json FROM incidents ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		log.Printf("store: query incidents error: %v", err)
		return nil
	}
	defer rows.Close()

	var list []model.IncidentReport
	for rows.Next() {
		var reportJSON string
		if err := rows.Scan(&reportJSON); err == nil {
			var inc model.IncidentReport
			if err := json.Unmarshal([]byte(reportJSON), &inc); err == nil {
				list = append(list, inc)
			}
		}
	}
	return list
}

// PutAudit records a policy/control change. The store stamps the timestamp so
// callers never thread a clock. Audit rows are intentionally never pruned — a
// promotion must not be evicted by file-open noise the way events are.
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
}

func (s *Store) RecentAudit(limit int) []AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`SELECT id, ts, action, rule, from_mode, to_mode, detail FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		log.Printf("store: query audit error: %v", err)
		return nil
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var a AuditEntry
		if err := rows.Scan(&a.ID, &a.TS, &a.Action, &a.Rule, &a.FromMode, &a.ToMode, &a.Detail); err == nil {
			out = append(out, a)
		}
	}
	return out
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
