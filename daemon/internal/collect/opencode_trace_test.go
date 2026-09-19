package collect

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"

	_ "modernc.org/sqlite"
)

// opencode part rows are JSON in another app's schema, so the mapping is
// pinned directly against real samples.
func TestOpencodeToolPartMapping(t *testing.T) {
	// A completed tool call with start/end times and an exit status.
	data := `{"type":"tool","tool":"bash","callID":"tool_1","state":{"status":"completed","input":{"command":"ls"},"output":"(no output)","metadata":{"exit":0},"title":"ls","time":{"start":1784907206968,"end":1784907206990}}}`
	evs := OpencodePartEvents("ses_abc", data, 1784907206990)
	if len(evs) != 1 {
		t.Fatalf("evs = %+v, want 1", evs)
	}
	e := evs[0]
	if e.Kind != event.KindToolCall || e.ToolName != "bash" || e.ToolStatus != "ok" {
		t.Fatalf("tool_call = %+v", e)
	}
	if e.DurationMs != 22 {
		t.Fatalf("duration = %dms, want 22", e.DurationMs)
	}
	if e.SessionID != "ses_abc" {
		t.Fatalf("session = %q", e.SessionID)
	}
	// Content (the command/output) never crosses into the event.
	if e.Detail != "" || e.Path != "" {
		t.Fatalf("tool_call carries content: %+v", e)
	}

	// An errored tool call maps to error status.
	errd := `{"type":"tool","tool":"bash","state":{"status":"error","time":{"start":1,"end":2}}}`
	if evs := OpencodePartEvents("s", errd, 2); len(evs) != 1 || evs[0].ToolStatus != "error" {
		t.Fatalf("error tool = %+v", evs)
	}
}

func TestOpencodeStepFinishIsModelCall(t *testing.T) {
	data := `{"type":"step-finish","reason":"tool-calls","tokens":{"total":15372,"input":15143,"output":229,"reasoning":0,"cache":{"write":0,"read":0}},"cost":0.0031}`
	evs := OpencodePartEvents("ses_x", data, 1784907207000)
	if len(evs) != 1 {
		t.Fatalf("evs = %+v", evs)
	}
	e := evs[0]
	if e.Kind != event.KindModelCall || e.TokensIn != 15143 || e.TokensOut != 229 {
		t.Fatalf("model_call = %+v", e)
	}
	if e.CostUSD != 0.0031 {
		t.Fatalf("cost = %v, want opencode's own 0.0031", e.CostUSD)
	}
}

func TestOpencodeIgnoresNonTraceParts(t *testing.T) {
	for _, data := range []string{
		`{"type":"text","text":"hello"}`,
		`{"type":"reasoning","text":"thinking"}`,
		`{"type":"step-start"}`,
		`{"type":"patch"}`,
		`not json`,
	} {
		if evs := OpencodePartEvents("s", data, 1); len(evs) != 0 {
			t.Fatalf("part %q produced events: %+v", data, evs)
		}
	}
}

func TestOpencodeDBAvailable(t *testing.T) {
	if OpencodeDBAvailable("/nonexistent/opencode.db") {
		t.Fatal("missing db must not read as available")
	}
}

// End-to-end over a real (temp) SQLite DB: the collector opens it read-only,
// reads parts past the watermark once, and never writes. This is the CI-safe
// analogue of pointing it at the live opencode DB.
func TestOpencodeCollectorReadsWatermarkedDB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "opencode.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	stmts := []string{
		`CREATE TABLE session (id TEXT PRIMARY KEY, directory TEXT, time_updated INTEGER)`,
		`CREATE TABLE part (id TEXT PRIMARY KEY, session_id TEXT, time_created INTEGER, time_updated INTEGER, data TEXT)`,
		`INSERT INTO session VALUES ('ses_1','/Users/dev/proj',100)`,
		`INSERT INTO part VALUES ('p1','ses_1',100,100,'{"type":"tool","tool":"read","state":{"status":"completed","time":{"start":100,"end":150}}}')`,
	}
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("setup %q: %v", q, err)
		}
	}
	db.Close()

	b := bus.New(16)
	sub := b.Subscribe()
	c := NewOpencodeCollector(b, path, 0)

	// Prime to "now" so the historical row (time_updated 100) is behind the
	// watermark — the live tail is what a running daemon reads.
	c.watermark = 100
	// Add a new part past the watermark.
	db2, _ := sql.Open("sqlite", path)
	_, _ = db2.Exec(`INSERT INTO part VALUES ('p2','ses_1',200,200,'{"type":"step-finish","tokens":{"input":1000,"output":50},"cost":0.002}')`)
	db2.Close()

	if n := c.pollOnce(); n != 1 {
		t.Fatalf("pollOnce published %d events, want 1 (the new part)", n)
	}
	select {
	case e := <-sub:
		if e.Kind != event.KindModelCall || e.TokensIn != 1000 {
			t.Fatalf("event = %+v", e)
		}
	default:
		t.Fatal("no event published")
	}
	// Watermark advanced: a second poll sees nothing new.
	if n := c.pollOnce(); n != 0 {
		t.Fatalf("second poll published %d, want 0 (watermark)", n)
	}
	// The collector must not have created WAL sidecars (read-only open).
	if _, err := os.Stat(path + "-wal"); err == nil {
		t.Fatal("read-only collector created a WAL file — it must never write")
	}
}
