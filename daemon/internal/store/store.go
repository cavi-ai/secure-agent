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
	mu        sync.Mutex
	db        *sql.DB
	jsonlFile *os.File
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

	// Ring buffer retention: cap events table at 10,000 entries
	_, _ = s.db.Exec(`DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 10000)`)
}

func (s *Store) RecentFlags(limit int) []model.Flag {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`SELECT id, rule, severity, ts, pid, agent, evidence FROM flags ORDER BY ts DESC LIMIT ?`, limit)
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
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`SELECT kind, ts, pid, exe_path, path, remote_host, remote_port, detail FROM events ORDER BY id DESC LIMIT ?`, limit)
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
