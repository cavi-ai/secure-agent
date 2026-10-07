package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func migrationFixture(t *testing.T, schema string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOpenMigratesPreSessionEvents(t *testing.T) {
	path := migrationFixture(t, `CREATE TABLE events (id INTEGER PRIMARY KEY, kind INT, ts TEXT, pid INT, exe_path TEXT, path TEXT, remote_host TEXT, remote_port INT, detail TEXT);
	INSERT INTO events VALUES (1,8,'2026-10-07T00:00:00Z',42,'agent','/file','',0,'preserved')`)
	for range 2 {
		s, err := Open(path, "")
		if err != nil {
			t.Fatal(err)
		}
		var detail string
		err = s.db.QueryRow(`SELECT detail FROM events WHERE id=1`).Scan(&detail)
		s.Close()
		if err != nil || detail != "preserved" {
			t.Fatalf("legacy event lost: %q, %v", detail, err)
		}
	}
}

func TestOpenRepairsPartialIncidentMigration(t *testing.T) {
	path := migrationFixture(t, `CREATE TABLE incidents (id TEXT PRIMARY KEY, flag_id TEXT, pid INT, risk TEXT, report_json TEXT, created_at TEXT, status TEXT, aggregate_count INTEGER);
	INSERT INTO incidents VALUES ('i','f',42,'high','{}','2026-10-07T00:00:00Z','open',2)`)
	s, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, col := range []string{"acknowledged_at", "resolved_at", "resolution_note", "rule", "session_id", "subject", "last_flag_at", "flag_ids"} {
		var n int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('incidents') WHERE name=?`, col).Scan(&n); err != nil || n != 1 {
			t.Fatalf("missing %s: %d, %v", col, n, err)
		}
	}
}

func TestFailedMigrationRollsBackSchema(t *testing.T) {
	path := migrationFixture(t, `CREATE TABLE events (id INTEGER PRIMARY KEY, kind INT, pid INT)`)
	if s, err := Open(path, ""); err == nil {
		s.Close()
		t.Fatal("invalid legacy schema accepted")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='flags'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("failed migration committed tables: %d, %v", n, err)
	}
}

func TestOpenRejectsFutureSchema(t *testing.T) {
	path := migrationFixture(t, `PRAGMA user_version=2147483647`)
	if s, err := Open(path, ""); err == nil {
		s.Close()
		t.Fatal("future schema accepted")
	}
}

func TestOpenReplacesLegacyModelTimestampIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	s, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DROP INDEX idx_events_turn_dedupe;
		CREATE UNIQUE INDEX idx_events_turn_dedupe ON events(kind,session_id,ts) WHERE kind IN (13,14) AND session_id!='';
		INSERT INTO events(kind,session_id,ts,call_id) VALUES (14,'s','2026-10-07T00:00:00Z','a');
		PRAGMA user_version=0`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	for range 2 {
		s, err = Open(path, "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`INSERT INTO events(kind,session_id,ts,call_id) VALUES (14,'s','2026-10-07T00:00:00Z',NULL)`); err != nil {
			t.Fatal(err)
		}
		var n int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE call_id='a'`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("upgrade lost existing model call: %d %v", n, err)
		}
		s.Close()
	}
}
