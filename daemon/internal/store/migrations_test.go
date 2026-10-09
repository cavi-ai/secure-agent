package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
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
	for _, version := range []int{0, 1, 2, 3} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			path := migrationFixture(t, fmt.Sprintf(`CREATE TABLE events (id INTEGER PRIMARY KEY, kind INT, pid INT);
		INSERT INTO events VALUES (1,8,42); PRAGMA user_version=%d`, version))
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
			var actualVersion, pid int
			if err := db.QueryRow(`PRAGMA user_version`).Scan(&actualVersion); err != nil || actualVersion != version {
				t.Fatalf("failed migration changed schema version: %d, %v", actualVersion, err)
			}
			if err := db.QueryRow(`SELECT pid FROM events WHERE id=1`).Scan(&pid); err != nil || pid != 42 {
				t.Fatalf("failed migration changed existing row: %d, %v", pid, err)
			}
		})
	}
}

func TestOpenRejectsFutureSchema(t *testing.T) {
	for _, version := range []int{4, 2147483647} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			path := migrationFixture(t, fmt.Sprintf(`CREATE TABLE future_evidence (id TEXT PRIMARY KEY);
		INSERT INTO future_evidence VALUES ('preserved'); PRAGMA user_version=%d`, version))
			if s, err := Open(path, ""); err == nil {
				s.Close()
				t.Fatal("future schema accepted")
			} else if !strings.Contains(err.Error(), fmt.Sprintf("unsupported database schema version %d", version)) {
				t.Fatalf("unexpected rejection: %v", err)
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var actualVersion, rows, tables int
			if err := db.QueryRow(`PRAGMA user_version`).Scan(&actualVersion); err != nil || actualVersion != version {
				t.Fatalf("rejection changed version: %d, %v", actualVersion, err)
			}
			if err := db.QueryRow(`SELECT COUNT(*) FROM future_evidence WHERE id='preserved'`).Scan(&rows); err != nil || rows != 1 {
				t.Fatalf("rejection lost evidence: %d, %v", rows, err)
			}
			if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='flags'`).Scan(&tables); err != nil || tables != 0 {
				t.Fatalf("rejection created a partial schema: %d, %v", tables, err)
			}
		})
	}
}

func TestSchemaBridgeKeepsLegacyDatabasesAtVersionTwo(t *testing.T) {
	for _, version := range []int{0, 1, 2} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			path := migrationFixture(t, fmt.Sprintf(`CREATE TABLE events (id INTEGER PRIMARY KEY, kind INT, ts TEXT, pid INT, exe_path TEXT, path TEXT, remote_host TEXT, remote_port INT, detail TEXT);
				INSERT INTO events VALUES (1,8,'2026-10-08T00:00:00Z',42,'agent','/seeded/file','',0,'preserved'); PRAGMA user_version=%d`, version))
			for range 2 {
				s, err := Open(path, "")
				if err != nil {
					t.Fatal(err)
				}
				var actualVersion int
				var detail string
				if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&actualVersion); err != nil || actualVersion != 2 {
					t.Fatalf("bridge advanced legacy database to %d: %v", actualVersion, err)
				}
				if err := s.db.QueryRow(`SELECT detail FROM events WHERE id=1`).Scan(&detail); err != nil || detail != "preserved" {
					t.Fatalf("bridge lost legacy evidence: %q, %v", detail, err)
				}
				s.Close()
			}
		})
	}
}

func TestSchemaBridgePreservesVersionThreeMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v3.db")
	s, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	// Synthetic additive metadata, not a declaration of the future schema.
	if _, err := s.db.Exec(`CREATE TABLE future_review_metadata (id TEXT PRIMARY KEY, metadata TEXT NOT NULL);
		CREATE TABLE future_scope_metadata (id TEXT PRIMARY KEY, metadata TEXT NOT NULL);
		INSERT INTO future_review_metadata VALUES ('review-1','{"revision":7,"state":"reviewed"}');
		INSERT INTO future_scope_metadata VALUES ('scope-1','{"expires_at":"2026-10-09T00:00:00Z"}');
		ALTER TABLE flags ADD COLUMN future_metadata TEXT;
		INSERT INTO flags(id,rule,severity,ts,pid,agent,evidence,acknowledged,future_metadata)
		VALUES ('f','sensitive-read-then-connect',3,'2026-10-08T00:00:00Z',42,'seeded','["preserved evidence"]','2026-10-08T00:01:00Z','preserved extension');
		PRAGMA user_version=3`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	for range 2 {
		s, err = Open(path, "")
		if err != nil {
			t.Fatal(err)
		}
		var version int
		if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 3 {
			t.Fatalf("bridge lowered version: %d, %v", version, err)
		}
		f, ok := s.GetFlag("f")
		if !ok || f.Severity != 3 || !f.Acknowledged || len(f.Evidence) != 1 || f.Evidence[0].String() != "preserved evidence" {
			t.Fatalf("old read model lost canonical evidence: %+v", f)
		}
		for _, row := range []struct{ query, want string }{
			{`SELECT metadata FROM future_review_metadata WHERE id='review-1'`, `{"revision":7,"state":"reviewed"}`},
			{`SELECT metadata FROM future_scope_metadata WHERE id='scope-1'`, `{"expires_at":"2026-10-09T00:00:00Z"}`},
			{`SELECT future_metadata FROM flags WHERE id='f'`, "preserved extension"},
		} {
			var got string
			if err := s.db.QueryRow(row.query).Scan(&got); err != nil || got != row.want {
				t.Fatalf("bridge changed additive metadata: %q, %v", got, err)
			}
		}
		s.Close()
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
