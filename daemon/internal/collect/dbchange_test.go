package collect

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
)

// settledClock reads every fingerprint as older than dbSettle, so a test can
// write and poll back to back.
func settledClock() time.Time { return time.Now().Add(time.Minute) }

func execAll(t *testing.T, db *sql.DB, stmts ...string) {
	t.Helper()
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%q: %v", q, err)
		}
	}
}

func TestFingerprintDBMovesOnWriteAndWALAppend(t *testing.T) {
	dir := t.TempDir()
	if fp := fingerprintDB(filepath.Join(dir, "absent.db")); !fp.equal(dbFingerprint{}) {
		t.Fatalf("missing database fingerprint = %+v, want zero", fp)
	}

	// Rollback journal: a write lands in the main file.
	plain := filepath.Join(dir, "plain.db")
	db, err := sql.Open("sqlite", plain)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	execAll(t, db, `CREATE TABLE t (v TEXT)`)
	before := fingerprintDB(plain)
	if again := fingerprintDB(plain); !again.equal(before) {
		t.Fatalf("unchanged database: %+v then %+v", before, again)
	}
	execAll(t, db, `INSERT INTO t VALUES ('a')`)
	if after := fingerprintDB(plain); after.equal(before) {
		t.Fatalf("write left the fingerprint at %+v", after)
	}

	// WAL: a commit appends to -wal and leaves the main file alone.
	walPath := filepath.Join(dir, "wal.db")
	wdb, err := sql.Open("sqlite", walPath)
	if err != nil {
		t.Fatal(err)
	}
	defer wdb.Close()
	wdb.SetMaxOpenConns(1)
	execAll(t, wdb, `PRAGMA journal_mode=WAL`, `PRAGMA wal_autocheckpoint=0`, `CREATE TABLE t (v TEXT)`)
	before = fingerprintDB(walPath)
	if before.walSize == 0 {
		t.Fatalf("WAL database has no -wal: %+v", before)
	}
	if again := fingerprintDB(walPath); !again.equal(before) {
		t.Fatalf("unchanged WAL database: %+v then %+v", before, again)
	}
	execAll(t, wdb, `INSERT INTO t VALUES ('a')`)
	after := fingerprintDB(walPath)
	if after.walSize <= before.walSize || after.size != before.size {
		t.Fatalf("WAL append: %+v then %+v, want only the -wal grown", before, after)
	}
}

func TestDBChangeSkipsOnlyASettledUnchangedDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	execAll(t, db, `CREATE TABLE t (v TEXT)`)

	// A database written within dbSettle is never recorded as unchanged.
	fresh := dbChange{}
	fp, run := fresh.begin(path)
	fresh.done(fp)
	if _, run2 := fresh.begin(path); !run || !run2 {
		t.Fatalf("fresh database: first run %v, second run %v, want both", run, run2)
	}

	c := dbChange{now: settledClock}
	fp, run = c.begin(path)
	if !run {
		t.Fatal("first poll skipped")
	}
	if _, run = c.begin(path); !run {
		t.Fatal("poll skipped before any poll recorded the database")
	}
	c.done(fp)
	if _, run = c.begin(path); run {
		t.Fatal("unchanged database polled again")
	}
	execAll(t, db, `INSERT INTO t VALUES ('a')`)
	if _, run = c.begin(path); !run {
		t.Fatal("changed database skipped")
	}
	if c.polls != 3 {
		t.Fatalf("polls = %d, want 3", c.polls)
	}
}

func TestOpencodeSkipsPollOfUnchangedDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "opencode.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	execAll(t, db,
		`CREATE TABLE session (id TEXT PRIMARY KEY, directory TEXT, time_updated INTEGER)`,
		`CREATE TABLE part (id TEXT PRIMARY KEY, session_id TEXT, time_created INTEGER, time_updated INTEGER, data TEXT)`,
		`INSERT INTO session VALUES ('ses_1','/Users/dev/proj',100)`,
		`INSERT INTO part VALUES ('p1','ses_1',100,100,'{"type":"tool","tool":"read","state":{"status":"completed","time":{"start":100,"end":150}}}')`)
	c := NewOpencodeCollector(bus.New(16), path, 0)
	c.change.now = settledClock
	c.watermark = 100

	c.pollOnce()
	c.pollOnce()
	if c.change.polls != 1 {
		t.Fatalf("two polls of an unchanged database queried %d times, want 1", c.change.polls)
	}
	execAll(t, db, `INSERT INTO part VALUES ('p2','ses_1',200,200,'{"type":"step-finish","tokens":{"input":1000,"output":50},"cost":0.002}')`)
	if n := c.pollOnce(); n != 1 || c.change.polls != 2 {
		t.Fatalf("after a write: published %d, polls %d, want 1 and 2", n, c.change.polls)
	}
	// The poll that read rows does not record: the next one confirms nothing
	// is left, then polls stop.
	c.pollOnce()
	c.pollOnce()
	if c.change.polls != 3 {
		t.Fatalf("polls = %d, want 3", c.change.polls)
	}
}

func TestOpenclawSkipsPollOfUnchangedDB(t *testing.T) {
	dir, db := openclawFixture(t)
	c, sub, _, _ := newTestOpenclaw(t, dir)
	c.change.now = settledClock
	drainOpenclaw(sub, c.pollOnce())
	c.pollOnce()
	c.pollOnce()
	c.pollOnce()
	if c.change.polls != 2 {
		t.Fatalf("polls = %d, want 2 (the backlog, then one empty read)", c.change.polls)
	}
	execAll(t, db, `INSERT INTO messages (message_id, conversation_id, seq, role, content, token_count, created_at)
		VALUES (7, 2, 2, 'user', 'x', 1, '2026-09-23 07:02:00')`)
	if n := c.pollOnce(); n != 1 || c.change.polls != 3 {
		t.Fatalf("after a write: published %d, polls %d, want 1 and 3", n, c.change.polls)
	}
	<-sub
}

func TestHermesSkipsPollOfUnchangedDB(t *testing.T) {
	root, main, _ := hermesFixture(t)
	c, sub, _, _ := newTestHermes(t, root)
	drainOpenclaw(sub, c.pollOnce())
	mainDB, workDB := c.dbs[filepath.Join(root, "state.db")], c.dbs[filepath.Join(root, "profiles", "work", "state.db")]
	if mainDB == nil || workDB == nil {
		t.Fatalf("databases = %v", c.dbs)
	}
	mainDB.change.now, workDB.change.now = settledClock, settledClock
	c.pollOnce()
	c.pollOnce()
	c.pollOnce()
	if mainDB.change.polls != 2 || workDB.change.polls != 2 {
		t.Fatalf("polls = %d and %d, want 2 each", mainDB.change.polls, workDB.change.polls)
	}
	execAll(t, main, fmt.Sprintf(`INSERT INTO messages (id, session_id, role, content, timestamp, token_count)
		VALUES (6, 's-child', 'user', 'x', %f, 1)`, hermesT0+50))
	if n := c.pollOnce(); n == 0 || mainDB.change.polls != 3 || workDB.change.polls != 2 {
		t.Fatalf("after a write to one database: published %d, polls %d and %d, want >0, 3 and 2", n, mainDB.change.polls, workDB.change.polls)
	}
	if st := c.Status(); st.LastError != "" || st.DBs[0].Watermark != 6 {
		t.Fatalf("status = %+v", st)
	}
}
