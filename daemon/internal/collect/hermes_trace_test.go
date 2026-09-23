package collect

import (
	"database/sql"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// hermesDDL is Hermes Agent's state.db schema (developer-guide/session-storage,
// schema version 23): the documented sessions and messages columns, content
// columns included so the test proves they never reach an event.
// session_model_usage's columns are not documented; this shape is an
// assumption the collector does not depend on (it reads PRAGMA table_info).
const hermesDDL = `
CREATE TABLE sessions (
  id TEXT PRIMARY KEY, source TEXT NOT NULL, user_id TEXT, model TEXT, model_config TEXT,
  system_prompt TEXT, parent_session_id TEXT, started_at REAL NOT NULL, ended_at REAL, end_reason TEXT,
  message_count INTEGER DEFAULT 0, tool_call_count INTEGER DEFAULT 0,
  input_tokens INTEGER DEFAULT 0, output_tokens INTEGER DEFAULT 0, cache_read_tokens INTEGER DEFAULT 0,
  cache_write_tokens INTEGER DEFAULT 0, reasoning_tokens INTEGER DEFAULT 0,
  billing_provider TEXT, billing_base_url TEXT, billing_mode TEXT,
  estimated_cost_usd REAL, actual_cost_usd REAL, cost_status TEXT, cost_source TEXT, pricing_version TEXT,
  cwd TEXT, git_branch TEXT, git_repo_root TEXT, title TEXT);
CREATE TABLE messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL REFERENCES sessions(id),
  role TEXT NOT NULL, content TEXT, tool_call_id TEXT, tool_calls TEXT, tool_name TEXT,
  timestamp REAL NOT NULL, token_count INTEGER, finish_reason TEXT, reasoning TEXT);`

const hermesUsageDDL = `
CREATE TABLE session_model_usage (
  id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, model TEXT NOT NULL, task TEXT,
  input_tokens INTEGER DEFAULT 0, output_tokens INTEGER DEFAULT 0, estimated_cost_usd REAL);`

const hermesSecret = "SECRET-CONTENT-never-in-an-event"

// hermesT0 is the fixture's first message time, epoch seconds.
const hermesT0 = 1790150400.0 // 2026-09-23T08:00:00Z

func hermesExec(t *testing.T, db *sql.DB, stmts ...string) {
	t.Helper()
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("%v\n%s", err, s)
		}
	}
}

// hermesFixture writes a Hermes root with two databases:
//   - <root>/state.db (with session_model_usage): s-child, a continuation of
//     s-root in a git checkout — a user turn, two tool calls (one ok after
//     2.5s, one failed after 1s) and an assistant reply with token_count;
//     three usage rows over two models.
//   - <root>/profiles/work/state.db (no usage table): p-1, a telegram session
//     already ended — a user turn and an assistant reply with token_count.
func hermesFixture(t *testing.T) (root string, main, work *sql.DB) {
	t.Helper()
	root = t.TempDir()
	open := func(path string) *sql.DB {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		return db
	}
	main = open(filepath.Join(root, "state.db"))
	calls := fmt.Sprintf(`[{"id":"call-1","type":"function","function":{"name":"terminal","arguments":"%[1]s"}},`+
		`{"id":"call-2","type":"function","function":{"name":"read_file","arguments":"%[1]s"}},"%[1]s"]`, hermesSecret)
	hermesExec(t, main, hermesDDL, hermesUsageDDL,
		fmt.Sprintf(`INSERT INTO sessions (id, source, model, system_prompt, parent_session_id, started_at, input_tokens, cwd, git_branch, git_repo_root, title) VALUES
		 ('s-root', 'cli', 'claude-sonnet-4-5', '%[1]s', NULL, %[2]f, 10, '/Users/x/src/proj', 'feat/x', '/Users/x/src/proj', '%[1]s'),
		 ('s-child', 'cli', 'claude-sonnet-4-5', '%[1]s', 's-root', %[2]f, 1500, '/Users/x/src/proj/sub', 'feat/x', '/Users/x/src/proj', '%[1]s')`, hermesSecret, hermesT0),
		fmt.Sprintf(`INSERT INTO messages (id, session_id, role, content, tool_call_id, tool_calls, tool_name, timestamp, token_count, finish_reason, reasoning) VALUES
		 (1, 's-child', 'user', '%[1]s', NULL, NULL, NULL, %[2]f, 7, NULL, NULL),
		 (2, 's-child', 'assistant', '%[1]s', NULL, '%[3]s', NULL, %[2]f + 1, NULL, 'tool_calls', '%[1]s'),
		 (3, 's-child', 'tool', '%[1]s', 'call-1', NULL, 'terminal', %[2]f + 3.5, NULL, NULL, NULL),
		 (4, 's-child', 'tool', '%[1]s', 'call-2', NULL, NULL, %[2]f + 2, NULL, 'error', NULL),
		 (5, 's-child', 'assistant', '%[1]s', NULL, 'not json', NULL, %[2]f + 4, 120, 'stop', '%[1]s')`, hermesSecret, hermesT0, calls),
		`INSERT INTO session_model_usage (session_id, model, task, input_tokens, output_tokens, estimated_cost_usd) VALUES
		 ('s-child', 'claude-sonnet-4-5', 'main', 1000, 100, 0.02),
		 ('s-child', 'claude-sonnet-4-5', 'compress', 500, 20, 0.005),
		 ('s-child', 'gpt-5', 'vision', 50, 10, NULL)`)

	work = open(filepath.Join(root, "profiles", "work", "state.db"))
	hermesExec(t, work, hermesDDL,
		fmt.Sprintf(`INSERT INTO sessions (id, source, model, billing_provider, started_at, ended_at, input_tokens) VALUES
		 ('p-1', 'telegram', 'gpt-5', 'openrouter', %[1]f, %[1]f + 60, 800)`, hermesT0),
		fmt.Sprintf(`INSERT INTO messages (id, session_id, role, content, timestamp, token_count) VALUES
		 (1, 'p-1', 'user', '%[1]s', %[2]f + 10, 3),
		 (2, 'p-1', 'assistant', '%[1]s', %[2]f + 11, 40)`, hermesSecret, hermesT0))
	return root, main, work
}

type hermesEnd struct {
	id string
	at time.Time
}

func newTestHermes(t *testing.T, root string) (*HermesCollector, <-chan event.Event, *[]HermesSighting, *[]hermesEnd) {
	t.Helper()
	b := bus.New(64)
	sub := b.Subscribe()
	c := NewHermesCollector(b, time.Second)
	c.Configured = root
	var seen []HermesSighting
	var ended []hermesEnd
	c.OnSessionSeen = func(s HermesSighting) { seen = append(seen, s) }
	c.OnSessionEnded = func(id string, at time.Time) { ended = append(ended, hermesEnd{id, at}) }
	return c, sub, &seen, &ended
}

func hermesAt(offset float64) time.Time {
	return time.Unix(0, int64((hermesT0+offset)*1e9)).UTC()
}

func TestHermesPollEmitsTrace(t *testing.T) {
	root, _, _ := hermesFixture(t)
	c, sub, seen, ended := newTestHermes(t, root)

	n := c.pollOnce()
	if n != 9 {
		t.Fatalf("pollOnce published %d events, want 9 (2 turns, 4 tool rows, 3 model calls)", n)
	}
	evs := drainOpenclaw(sub, n)

	wantSeen := []HermesSighting{
		{ID: "s-child", Workspace: "/Users/x/src/proj/sub", Repo: "proj", Branch: "feat/x", ParentID: "s-root", At: hermesAt(0)},
		{ID: "p-1", Workspace: "hermes:telegram", At: hermesAt(0)},
	}
	if fmt.Sprint(*seen) != fmt.Sprint(wantSeen) {
		t.Fatalf("sessions noted = %+v\nwant %+v", *seen, wantSeen)
	}
	var turns []string
	calls := map[string]event.Event{}
	models := map[string]event.Event{}
	for _, e := range evs {
		if strings.Contains(fmt.Sprintf("%+v", e), hermesSecret) {
			t.Fatalf("event carries content: %+v", e)
		}
		switch e.Kind {
		case event.KindTurn:
			turns = append(turns, e.SessionID)
		case event.KindToolCall:
			calls[e.CallID+"/"+e.ToolStatus] = e
		case event.KindModelCall:
			models[e.SessionID+"/"+e.Model] = e
		}
	}
	if fmt.Sprint(turns) != "[s-child p-1]" {
		t.Fatalf("turns = %v, want one per user message", turns)
	}
	start := hermesAt(1)
	if e, ok := calls["call-1/running"]; !ok || e.ToolName != "terminal" || e.SessionID != "s-child" || !e.TS.Equal(start) {
		t.Fatalf("call-1 start = %+v (ok=%v)", e, ok)
	}
	if e, ok := calls["call-2/running"]; !ok || e.ToolName != "read_file" || !e.TS.Equal(start) {
		t.Fatalf("call-2 start = %+v (ok=%v)", e, ok)
	}
	if e, ok := calls["call-1/ok"]; !ok || e.ToolName != "terminal" || e.DurationMs != 2500 || !e.TS.Equal(start) {
		t.Fatalf("call-1 completion = %+v (ok=%v), want ok in 2500ms", e, ok)
	}
	if e, ok := calls["call-2/error"]; !ok || e.ToolName != "read_file" || e.DurationMs != 1000 {
		t.Fatalf("call-2 completion = %+v (ok=%v), want error in 1000ms with the call's tool name", e, ok)
	}
	// session_model_usage present: one model call per model, its totals.
	if e, ok := models["s-child/claude-sonnet-4-5"]; !ok || e.TokensIn != 1500 || e.TokensOut != 120 || math.Abs(e.CostUSD-0.025) > 1e-9 {
		t.Fatalf("usage model call (claude) = %+v (ok=%v)", e, ok)
	}
	if e, ok := models["s-child/gpt-5"]; !ok || e.TokensIn != 50 || e.TokensOut != 10 || e.CostUSD != ModelCostUSD("gpt-5", 50, 10) || e.CostUSD == 0 {
		t.Fatalf("usage model call (gpt-5) = %+v (ok=%v), want priced from the model id", e, ok)
	}
	// No usage table: one model call per assistant message with token_count.
	if e, ok := models["p-1/gpt-5"]; !ok || e.TokensOut != 40 || e.TokensIn != 800 || e.Provider != "openrouter" ||
		e.CostUSD != ModelCostUSD("gpt-5", 800, 40) || !e.TS.Equal(hermesAt(11)) {
		t.Fatalf("message model call (p-1) = %+v (ok=%v)", e, ok)
	}
	if len(models) != 3 {
		t.Fatalf("model calls = %+v, want 3 (usage replaces the per-message call where the table exists)", models)
	}
	if fmt.Sprint(*ended) != fmt.Sprint([]hermesEnd{{"p-1", hermesAt(60)}}) {
		t.Fatalf("ended = %+v, want p-1 at its ended_at", *ended)
	}
	st := c.Status()
	if len(st.DBs) != 2 || st.DBs[0].Path != filepath.Join(root, "state.db") || st.DBs[0].Watermark != 5 ||
		st.DBs[1].Path != filepath.Join(root, "profiles", "work", "state.db") || st.DBs[1].Watermark != 2 ||
		st.LastPoll.IsZero() || st.LastError != "" {
		t.Fatalf("status = %+v", st)
	}

	// A second poll over unchanged databases emits nothing new.
	if n := c.pollOnce(); n != 0 {
		t.Fatalf("second poll published %d, want 0", n)
	}
}

func TestHermesUsageChangeAndEnd(t *testing.T) {
	root, main, _ := hermesFixture(t)
	c, sub, _, ended := newTestHermes(t, root)
	drainOpenclaw(sub, c.pollOnce())

	// Usage grows without a new message: the change is emitted once.
	hermesExec(t, main, `UPDATE session_model_usage SET input_tokens = input_tokens + 200, output_tokens = output_tokens + 30,
		estimated_cost_usd = estimated_cost_usd + 0.001 WHERE task = 'main'`)
	if n := c.pollOnce(); n != 1 {
		t.Fatalf("usage change published %d, want 1", n)
	}
	if e := <-sub; e.Kind != event.KindModelCall || e.Model != "claude-sonnet-4-5" || e.TokensIn != 200 || e.TokensOut != 30 ||
		math.Abs(e.CostUSD-0.001) > 1e-9 || e.SessionID != "s-child" {
		t.Fatalf("usage delta = %+v", e)
	}
	if n := c.pollOnce(); n != 0 {
		t.Fatalf("unchanged usage published %d, want 0", n)
	}

	// Hermes ends the session: ended once, at its ended_at.
	hermesExec(t, main, fmt.Sprintf(`UPDATE sessions SET ended_at = %f WHERE id = 's-child'`, hermesT0+30))
	c.pollOnce()
	c.pollOnce()
	if fmt.Sprint(*ended) != fmt.Sprint([]hermesEnd{{"p-1", hermesAt(60)}, {"s-child", hermesAt(30)}}) {
		t.Fatalf("ended = %+v", *ended)
	}
}

func TestHermesWatermarkPersists(t *testing.T) {
	root, main, _ := hermesFixture(t)
	state := filepath.Join(t.TempDir(), "hermes-watermark.json")
	c, sub, _, _ := newTestHermes(t, root)
	c.StatePath = state
	drainOpenclaw(sub, c.pollOnce())

	// A restarted collector resumes at the persisted watermarks: only the new
	// message is read, and usage already counted is not emitted again.
	hermesExec(t, main, fmt.Sprintf(`INSERT INTO messages (id, session_id, role, content, timestamp) VALUES
		(6, 's-child', 'user', 'x', %f)`, hermesT0+20))
	c2, sub2, _, _ := newTestHermes(t, root)
	c2.StatePath = state
	if n := c2.pollOnce(); n != 1 {
		t.Fatalf("restarted poll published %d, want 1 (the new turn)", n)
	}
	if e := <-sub2; e.Kind != event.KindTurn || e.SessionID != "s-child" || !e.TS.Equal(hermesAt(20)) {
		t.Fatalf("event = %+v", e)
	}
	if st := c2.Status(); st.DBs[0].Watermark != 6 {
		t.Fatalf("status = %+v, want the root db at 6", st)
	}
}

func TestHermesMissingRootIsSilentNoop(t *testing.T) {
	c := NewHermesCollector(bus.New(4), time.Second)
	c.Configured = filepath.Join(t.TempDir(), "absent")
	if n := c.pollOnce(); n != 0 {
		t.Fatalf("missing root published %d", n)
	}
	if n := c.pollOnce(); n != 0 {
		t.Fatalf("missing root published %d on the second poll", n)
	}
	if st := c.Status(); len(st.DBs) != 0 || st.Root != c.Configured || st.LastError != "" {
		t.Fatalf("status = %+v, want no databases under the configured root", st)
	}
}

func TestHermesHomeResolution(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if got := HermesHome("/cfg", env(map[string]string{"HERMES_HOME": "/env"}), "/home/u"); got != "/cfg" {
		t.Fatalf("configured = %q, want /cfg", got)
	}
	if got := HermesHome("", env(map[string]string{"HERMES_HOME": "/env"}), "/home/u"); got != "/env" {
		t.Fatalf("HERMES_HOME = %q, want /env", got)
	}
	if got := HermesHome("", env(nil), "/home/u"); got != filepath.Join("/home/u", ".hermes") {
		t.Fatalf("default = %q, want ~/.hermes", got)
	}
	if got := HermesHome("", env(nil), ""); got != "" {
		t.Fatalf("no home = %q, want empty", got)
	}
}

// With no configured root the collector follows $HERMES_HOME.
func TestHermesHonoursHermesHomeEnv(t *testing.T) {
	root, _, _ := hermesFixture(t)
	t.Setenv("HERMES_HOME", root)
	t.Setenv("HOME", t.TempDir())
	c, sub, _, _ := newTestHermes(t, "")
	n := c.pollOnce()
	if n != 9 {
		t.Fatalf("pollOnce via HERMES_HOME published %d, want 9", n)
	}
	drainOpenclaw(sub, n)
	if st := c.Status(); st.Root != root || len(st.DBs) != 2 {
		t.Fatalf("status = %+v, want root %s with 2 databases", st, root)
	}
}

// A database whose schema lacks a required column is reported, not read.
func TestHermesSchemaDriftReported(t *testing.T) {
	root := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(root, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	hermesExec(t, db, `CREATE TABLE sessions (id TEXT PRIMARY KEY)`, `CREATE TABLE messages (id INTEGER PRIMARY KEY, session_id TEXT, role TEXT)`,
		`INSERT INTO messages VALUES (1, 's', 'user')`)
	c, _, _, _ := newTestHermes(t, root)
	if n := c.pollOnce(); n != 0 {
		t.Fatalf("drifted schema published %d", n)
	}
	if st := c.Status(); len(st.DBs) != 1 || st.DBs[0].Watermark != 0 || !strings.Contains(st.LastError, "messages") {
		t.Fatalf("status = %+v, want the messages error and no progress", st)
	}
}
