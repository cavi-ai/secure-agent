package store

import (
	"database/sql"
	"errors"
	"time"
)

// monitor_runs holds each daemon run's start and the owner's stop intent, so
// the next start can confirm an owner stop that the run record reports.
const monitorRunsSchema = `CREATE TABLE IF NOT EXISTS monitor_runs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	pid INTEGER NOT NULL,
	started_at TEXT NOT NULL,
	stop_intent_at TEXT NOT NULL DEFAULT '',
	UNIQUE (pid, started_at)
)`

// maxMonitorRuns bounds the table to the most recent runs.
const maxMonitorRuns = 64

func monitorRunTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// PutMonitorRun records the start of one daemon run and drops the oldest
// runs past maxMonitorRuns.
func (s *Store) PutMonitorRun(pid int, startedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec(`INSERT INTO monitor_runs (pid, started_at) VALUES (?, ?)
		ON CONFLICT(pid, started_at) DO NOTHING`, pid, monitorRunTime(startedAt)); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM monitor_runs WHERE id NOT IN
		(SELECT id FROM monitor_runs ORDER BY id DESC LIMIT ?)`, maxMonitorRuns)
	return err
}

// PutMonitorStopIntent records the owner's stop intent for one run.
func (s *Store) PutMonitorStopIntent(pid int, startedAt, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO monitor_runs (pid, started_at, stop_intent_at) VALUES (?, ?, ?)
		ON CONFLICT(pid, started_at) DO UPDATE SET stop_intent_at = excluded.stop_intent_at`,
		pid, monitorRunTime(startedAt), monitorRunTime(at))
	return err
}

// MonitorRunStopIntent returns the stop intent stored for one run. found is
// false when no row exists for the run; a run with no stop intent returns the
// zero time.
func (s *Store) MonitorRunStopIntent(pid int, startedAt time.Time) (at time.Time, found bool, err error) {
	var raw string
	err = s.db.QueryRow(`SELECT stop_intent_at FROM monitor_runs WHERE pid = ? AND started_at = ?`,
		pid, monitorRunTime(startedAt)).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	if raw == "" {
		return time.Time{}, true, nil
	}
	at, err = time.Parse(time.RFC3339Nano, raw)
	return at, err == nil, err
}

// HasMonitorRuns reports whether any run is stored.
func (s *Store) HasMonitorRuns() (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM monitor_runs`).Scan(&n)
	return n > 0, err
}
