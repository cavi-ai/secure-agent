package store

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SessionIDForRoot returns a durable ID only when one stored session has the
// same root PID and exact root start instant. Ended sessions remain eligible.
func (s *Store) SessionIDForRoot(rootPID int32, rootStartedAt time.Time) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessionIDForRootLocked(rootPID, rootStartedAt)
}

// sessionIDForRootLocked is also used by resource capture while it holds
// s.mu through the insert. Callers must hold s.mu.
func (s *Store) sessionIDForRootLocked(rootPID int32, rootStartedAt time.Time) string {
	if rootPID <= 0 || rootStartedAt.IsZero() {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT id, root_started_at FROM sessions WHERE root_pid = ? AND root_started_at != ''`, rootPID)
	if err != nil {
		return ""
	}
	defer rows.Close()
	var match string
	for rows.Next() {
		var id, storedStart string
		if rows.Scan(&id, &storedStart) != nil {
			return ""
		}
		parsed, err := time.Parse(time.RFC3339Nano, storedStart)
		if err != nil || !parsed.Equal(rootStartedAt) {
			continue
		}
		if match != "" {
			return ""
		}
		match = id
	}
	if rows.Err() != nil {
		return ""
	}
	return match
}

// SessionIDForFamilyKey resolves an older episode's stored process-family
// key, never a workspace or time-proximity guess. Its exact PID/start lookup
// rejects missing and ambiguous durable sessions.
func (s *Store) SessionIDForFamilyKey(key string) string {
	pidText, startText, ok := strings.Cut(key, ":")
	if !ok {
		return ""
	}
	pid, err := strconv.ParseInt(pidText, 10, 32)
	if err != nil || pid <= 0 {
		return ""
	}
	nanos, err := strconv.ParseInt(startText, 10, 64)
	if err != nil || nanos <= 0 || fmt.Sprintf("%d:%d", pid, nanos) != key {
		return ""
	}
	return s.SessionIDForRoot(int32(pid), time.Unix(0, nanos).UTC())
}
