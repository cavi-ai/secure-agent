package store

import (
	"database/sql"
	"log"
	"time"
)

// scan_cache keeps the last result of a slow scan (the worktree report, the
// cleanup inventory, their measured sizes) so a restarted daemon answers
// from it at once and rescans in the background.
const scanCacheSchema = `CREATE TABLE IF NOT EXISTS scan_cache (
	name TEXT PRIMARY KEY,
	saved_at TEXT NOT NULL,
	body BLOB NOT NULL
)`

// PutScanCache replaces the named entry.
func (s *Store) PutScanCache(name string, body []byte, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec(`INSERT INTO scan_cache (name, saved_at, body) VALUES (?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET saved_at = excluded.saved_at, body = excluded.body`,
		name, at.UTC().Format(time.RFC3339Nano), body); err != nil {
		log.Printf("store: save scan cache %s: %v", name, err)
	}
}

// ScanCache returns the named entry and when it was saved.
func (s *Store) ScanCache(name string) ([]byte, time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var at string
	var body []byte
	err := s.db.QueryRow(`SELECT saved_at, body FROM scan_cache WHERE name = ?`, name).Scan(&at, &body)
	if err != nil {
		if err != sql.ErrNoRows {
			log.Printf("store: read scan cache %s: %v", name, err)
		}
		return nil, time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return nil, time.Time{}, false
	}
	return body, t, true
}
