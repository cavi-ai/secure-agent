package collect

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
)

func TestOpencodeDrainsTiesAndReconcilesLateChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "opencode.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE session (id TEXT PRIMARY KEY,directory TEXT);
	CREATE TABLE part (id TEXT PRIMARY KEY,session_id TEXT,time_updated INTEGER,data TEXT);
	INSERT INTO session VALUES ('s','/workspace')`); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxOpencodeRows*2+3; i++ {
		if _, err := tx.Exec(`INSERT INTO part VALUES (?,'s',200,?)`, fmt.Sprintf("p%04d", i), `{"type":"tool","tool":"read","callID":"`+fmt.Sprintf("c%d", i)+`","state":{"status":"running"}}`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO part VALUES ('bad','s',200,'malformed')`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	b := bus.New(maxOpencodeRows * 3)
	sub := b.Subscribe()
	c := NewOpencodeCollector(b, path, 0)
	c.watermark = 100
	total := 0
	for range 4 {
		total += c.pollOnce()
	}
	if total != maxOpencodeRows*2+3 {
		t.Fatalf("received %d tied rows, want %d", total, maxOpencodeRows*2+3)
	}
	for range total {
		<-sub
	}
	// Both changes sort behind the cursor and retain the consumed timestamp.
	if _, err := db.Exec(`INSERT INTO part VALUES ('a','s',200,'{"type":"step-finish","tokens":{"input":7,"output":3}}');
	UPDATE part SET data='{"type":"tool","tool":"read","callID":"c0","state":{"status":"completed"}}' WHERE id='p0000'`); err != nil {
		t.Fatal(err)
	}
	total = 0
	for range 4 {
		total += c.pollOnce()
	}
	if total != 2 {
		t.Fatalf("late insert/update produced %d events, want 2", total)
	}
	first, second := <-sub, <-sub
	if first.CallID == "" || first.TokensIn != 7 || second.CallID != "c0" || second.ToolStatus != "ok" {
		t.Fatalf("late identities/completion: %+v %+v", first, second)
	}
}

func TestOpencodeResumesMidBatchAndKeepsCheckpointPrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "opencode.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE session(id TEXT PRIMARY KEY,directory TEXT); CREATE TABLE part(id TEXT PRIMARY KEY,session_id TEXT,time_updated INTEGER,data TEXT)`); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxOpencodeRows+1; i++ {
		if _, err := tx.Exec(`INSERT INTO part VALUES (?,'s',200,'{"type":"step-finish","tokens":{"input":1,"output":1}}')`, fmt.Sprintf("p%04d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	c := NewOpencodeCollector(bus.New(maxOpencodeRows+1), path, 0)
	c.StatePath = filepath.Join(dir, "checkpoint.json")
	if n := c.pollOnce(); n != maxOpencodeRows {
		t.Fatalf("first batch %d", n)
	}
	resumed := NewOpencodeCollector(bus.New(16), path, 0)
	resumed.StatePath = c.StatePath
	if !resumed.loadState() {
		t.Fatal("checkpoint not loaded")
	}
	if n := resumed.pollOnce(); n != 1 {
		t.Fatalf("restart skipped or replayed batch: %d", n)
	}
	if info, err := os.Stat(c.StatePath); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("checkpoint permissions: %v %v", info, err)
	}
	other := NewOpencodeCollector(nil, filepath.Join(dir, "other.db"), 0)
	other.StatePath = c.StatePath
	if other.loadState() {
		t.Fatal("checkpoint from another source accepted")
	}
}

func TestOpencodeReplayCacheIsBounded(t *testing.T) {
	c := NewOpencodeCollector(nil, "unused.db", 0)
	for i := 0; i < maxOpencodeSeen*2; i++ {
		c.rememberPart(fmt.Sprint(i), "{}")
	}
	if len(c.seen) != maxOpencodeSeen || len(c.seenOrder) != maxOpencodeSeen {
		t.Fatalf("unbounded replay cache: %d %d", len(c.seen), len(c.seenOrder))
	}
	if c.rememberPart(fmt.Sprint(maxOpencodeSeen*2-1), "{}") {
		t.Fatal("unchanged retained part replayed")
	}
}
