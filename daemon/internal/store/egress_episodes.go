package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxEgressEpisodes  = 4096
	maxEgressQuery     = 500
	maxEgressIntervals = 16
	maxEgressSessions  = 8
	egressIdleExpiry   = 7 * 24 * time.Hour
	minRecurringGap    = time.Minute
	minRecurringCount  = 5
)

const egressEpisodesSchema = `CREATE TABLE IF NOT EXISTS egress_episodes (
 id TEXT PRIMARY KEY,
 agent TEXT NOT NULL, exe_path TEXT NOT NULL, harness TEXT NOT NULL, workspace TEXT NOT NULL,
 host TEXT NOT NULL, protocol TEXT NOT NULL, port INTEGER NOT NULL,
 count INTEGER NOT NULL, first_seen_ns INTEGER NOT NULL, last_seen_ns INTEGER NOT NULL,
 intervals_json TEXT NOT NULL, session_ids_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_egress_episodes_last ON egress_episodes(last_seen_ns DESC, id);`

// EgressScope identifies an observed activity. A complete scope requires a
// canonical executable path, harness, and workspace; PID and inferred task
// names are deliberately absent.
type EgressScope struct {
	Agent     string `json:"agent"`
	ExePath   string `json:"exe_path,omitempty"`
	Harness   string `json:"harness,omitempty"`
	Workspace string `json:"workspace,omitempty"`
}

type EgressObservation struct {
	Scope     EgressScope
	SessionID string
	Host      string
	Protocol  string
	Port      int
	At        time.Time
}

type EgressEpisode struct {
	ID            string          `json:"id"`
	Scope         EgressScope     `json:"scope"`
	SessionIDs    []string        `json:"session_ids"`
	Host          string          `json:"host"`
	Protocol      string          `json:"protocol"`
	Port          int             `json:"port"`
	Count         int             `json:"count"`
	FirstSeen     time.Time       `json:"first_seen"`
	LastSeen      time.Time       `json:"last_seen"`
	Intervals     []time.Duration `json:"intervals"`
	Recurring     bool            `json:"recurring"`
	ScopeComplete bool            `json:"scope_complete"`
}

func canonicalEgressPath(path string) string {
	if path == "" || !filepath.IsAbs(path) {
		return ""
	}
	path = filepath.Clean(path)
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return path
}

func normalizeEgressScope(scope EgressScope) EgressScope {
	scope.Agent = strings.TrimSpace(scope.Agent)
	scope.Harness = strings.TrimSpace(scope.Harness)
	scope.ExePath = canonicalEgressPath(scope.ExePath)
	scope.Workspace = canonicalEgressPath(scope.Workspace)
	return scope
}

func (s EgressScope) Complete() bool { return s.ExePath != "" && s.Harness != "" && s.Workspace != "" }

func normalizeEgressHost(host string) (string, error) {
	host = strings.TrimSpace(strings.ToLower(host))
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return ip.String(), nil
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/?#@:%\\ \t\r\n") {
		return "", errors.New("invalid destination")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid destination")
		}
		for _, c := range label {
			if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return "", errors.New("invalid destination")
			}
		}
	}
	return host, nil
}

func egressEpisodeID(o EgressObservation) string {
	key, _ := json.Marshal([]any{o.Scope.Agent, o.Scope.ExePath, o.Scope.Harness, o.Scope.Workspace, o.Host, o.Protocol, o.Port})
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:16])
}

func egressRecurring(e EgressEpisode) bool {
	if e.Count < minRecurringCount || len(e.Intervals) < 4 {
		return false
	}
	gaps := e.Intervals[len(e.Intervals)-4:]
	min, max := gaps[0], gaps[0]
	for _, gap := range gaps {
		if gap < minRecurringGap {
			return false
		}
		if gap < min {
			min = gap
		}
		if gap > max {
			max = gap
		}
	}
	return max <= 2*min
}

// RecordEgressObservation is a bounded, best-effort metadata projection. It
// intentionally accepts no URL, payload, command, or credential fields.
func (s *Store) RecordEgressObservation(o EgressObservation) error {
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	return s.recordEgressObservation(ctx, o)
}

// RecordEgressObservationForTest records o with no deadline. Test-only:
// fixtures must not drop observations on a loaded machine.
func (s *Store) RecordEgressObservationForTest(o EgressObservation) error {
	return s.recordEgressObservation(context.Background(), o)
}

func (s *Store) recordEgressObservation(ctx context.Context, o EgressObservation) error {
	if o.At.IsZero() || o.Port < 1 || o.Port > 65535 {
		return errors.New("invalid observation")
	}
	o.Protocol = strings.ToLower(strings.TrimSpace(o.Protocol))
	if o.Protocol != "tcp" && o.Protocol != "udp" {
		return errors.New("invalid protocol")
	}
	var err error
	o.Host, err = normalizeEgressHost(o.Host)
	if err != nil {
		return err
	}
	o.Scope = normalizeEgressScope(o.Scope)
	if o.Scope.Agent == "" {
		o.Scope.Agent = "unknown"
	}
	id := egressEpisodeID(o)
	s.egressMu.Lock()
	defer s.egressMu.Unlock()
	tx, err := s.beginImmediate(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var e EgressEpisode
	var first, last int64
	var intervalsJSON, sessionsJSON string
	err = tx.QueryRowContext(ctx, `SELECT count, first_seen_ns, last_seen_ns, intervals_json, session_ids_json FROM egress_episodes WHERE id=?`, id).Scan(&e.Count, &first, &last, &intervalsJSON, &sessionsJSON)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if err == sql.ErrNoRows {
		e.Count = 0
		first = o.At.UnixNano()
	} else {
		if err := json.Unmarshal([]byte(intervalsJSON), &e.Intervals); err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(sessionsJSON), &e.SessionIDs); err != nil {
			return err
		}
	}
	at := o.At.UnixNano()
	if e.Count > 0 && at > last {
		e.Intervals = append(e.Intervals, time.Duration(at-last))
		if len(e.Intervals) > maxEgressIntervals {
			e.Intervals = e.Intervals[len(e.Intervals)-maxEgressIntervals:]
		}
	}
	if at < first {
		first = at
	}
	if at > last {
		last = at
	}
	if e.Count == 0 {
		last = at
	}
	e.Count++
	if o.SessionID != "" {
		found := false
		for _, sid := range e.SessionIDs {
			if sid == o.SessionID {
				found = true
				break
			}
		}
		if !found {
			e.SessionIDs = append(e.SessionIDs, o.SessionID)
			if len(e.SessionIDs) > maxEgressSessions {
				e.SessionIDs = e.SessionIDs[len(e.SessionIDs)-maxEgressSessions:]
			}
		}
	}
	intervals, _ := json.Marshal(e.Intervals)
	sessions, _ := json.Marshal(e.SessionIDs)
	result, err := tx.ExecContext(ctx, `INSERT INTO egress_episodes (id,agent,exe_path,harness,workspace,host,protocol,port,count,first_seen_ns,last_seen_ns,intervals_json,session_ids_json)
	 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET count=excluded.count, first_seen_ns=excluded.first_seen_ns,
	 last_seen_ns=excluded.last_seen_ns, intervals_json=excluded.intervals_json, session_ids_json=excluded.session_ids_json`,
		id, o.Scope.Agent, o.Scope.ExePath, o.Scope.Harness, o.Scope.Workspace, o.Host, o.Protocol, o.Port, e.Count, first, last, string(intervals), string(sessions))
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return errors.New("egress observation was not persisted")
	}
	cutoff := time.Now().Add(-egressIdleExpiry).UnixNano()
	if _, err := tx.ExecContext(ctx, `DELETE FROM egress_episodes WHERE last_seen_ns < ?`, cutoff); err != nil {
		return err
	}
	var rowCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM egress_episodes`).Scan(&rowCount); err != nil {
		return err
	}
	if rowCount > maxEgressEpisodes {
		if _, err := tx.ExecContext(ctx, `DELETE FROM egress_episodes WHERE id IN
		 (SELECT id FROM egress_episodes ORDER BY last_seen_ns ASC, id ASC LIMIT ?)`, rowCount-maxEgressEpisodes); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// immediateTx is a write transaction that took SQLite's write lock at BEGIN.
// The episode projection reads, then writes, beside writers that hold s.mu
// instead of egressMu. A deferred transaction cannot upgrade its read to a
// write while another connection writes: SQLite fails it at once with
// SQLITE_BUSY or SQLITE_BUSY_SNAPSHOT, without waiting. BEGIN IMMEDIATE waits
// under the busy timeout, bounded by ctx.
type immediateTx struct {
	ctx  context.Context
	conn *sql.Conn
	done bool
}

func (s *Store) beginImmediate(ctx context.Context) (*immediateTx, error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &immediateTx{ctx: ctx, conn: conn}, nil
}

func (t *immediateTx) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return t.conn.QueryRowContext(ctx, query, args...)
}

func (t *immediateTx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return t.conn.ExecContext(ctx, query, args...)
}

func (t *immediateTx) Commit() error {
	if _, err := t.conn.ExecContext(t.ctx, "COMMIT"); err != nil {
		return err
	}
	t.done = true
	return nil
}

// Rollback ends an uncommitted transaction and returns the connection to the
// pool. A connection that cannot roll back is discarded, never handed to the
// next caller mid-transaction.
func (t *immediateTx) Rollback() {
	if !t.done {
		if _, err := t.conn.ExecContext(context.Background(), "ROLLBACK"); err != nil {
			_ = t.conn.Raw(func(any) error { return driver.ErrBadConn })
		}
	}
	_ = t.conn.Close()
}

func scanEgressEpisode(scanner interface{ Scan(...any) error }) (EgressEpisode, error) {
	var e EgressEpisode
	var first, last int64
	var intervals, sessions string
	err := scanner.Scan(&e.ID, &e.Scope.Agent, &e.Scope.ExePath, &e.Scope.Harness, &e.Scope.Workspace, &e.Host, &e.Protocol, &e.Port, &e.Count, &first, &last, &intervals, &sessions)
	if err != nil {
		return e, err
	}
	e.FirstSeen, e.LastSeen = time.Unix(0, first).UTC(), time.Unix(0, last).UTC()
	if err := json.Unmarshal([]byte(intervals), &e.Intervals); err != nil {
		return e, err
	}
	if err := json.Unmarshal([]byte(sessions), &e.SessionIDs); err != nil {
		return e, err
	}
	e.ScopeComplete = e.Scope.Complete()
	e.Recurring = egressRecurring(e)
	return e, nil
}

func (s *Store) GetEgressEpisode(id string) (EgressEpisode, bool) {
	row := s.db.QueryRow(`SELECT id,agent,exe_path,harness,workspace,host,protocol,port,count,first_seen_ns,last_seen_ns,intervals_json,session_ids_json FROM egress_episodes WHERE id=? AND last_seen_ns>=?`, id, time.Now().Add(-egressIdleExpiry).UnixNano())
	e, err := scanEgressEpisode(row)
	return e, err == nil
}

// ListEgressEpisodes returns newest-first rows under a fixed query cap.
func (s *Store) ListEgressEpisodes(limit int) []EgressEpisode {
	if limit <= 0 {
		limit = 100
	}
	if limit > maxEgressQuery {
		limit = maxEgressQuery
	}
	return s.listEgressEpisodes(limit)
}

// ListEgressEpisodesForReview reads the entire bounded projection so an older
// unresolved candidate cannot be hidden by newer one-off connections.
func (s *Store) ListEgressEpisodesForReview() []EgressEpisode {
	return s.listEgressEpisodes(maxEgressEpisodes)
}

func (s *Store) listEgressEpisodes(limit int) []EgressEpisode {
	rows, err := s.db.Query(`SELECT id,agent,exe_path,harness,workspace,host,protocol,port,count,first_seen_ns,last_seen_ns,intervals_json,session_ids_json FROM egress_episodes WHERE last_seen_ns>=? ORDER BY last_seen_ns DESC, id DESC LIMIT ?`, time.Now().Add(-egressIdleExpiry).UnixNano(), limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := make([]EgressEpisode, 0, min(limit, 128))
	for rows.Next() {
		e, err := scanEgressEpisode(rows)
		if err != nil {
			return out
		}
		out = append(out, e)
	}
	return out
}
