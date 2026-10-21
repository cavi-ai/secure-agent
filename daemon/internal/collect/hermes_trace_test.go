package collect

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
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
	// The fixture's messages are an hour old: all inside the first-sight window.
	c.now = func() time.Time { return hermesAt(3600) }
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

func TestHermesRetriesRejectedEventsAfterRestart(t *testing.T) {
	root, _, _ := hermesFixture(t)
	state := filepath.Join(t.TempDir(), "hermes-watermark.json")
	b := bus.New(1)
	sub := b.Subscribe()
	c := NewHermesCollector(b, time.Second)
	c.Configured = root
	c.StatePath = state
	c.now = func() time.Time { return hermesAt(3600) }
	c.pollOnce()
	// Re-poll the unchanged databases while the subscriber remains full, then
	// drain and retry without inserting rows or touching the source files.
	if n := c.pollOnce(); n != 0 {
		t.Fatalf("full subscriber accepted %d additional events", n)
	}
	var got []event.Event
	select {
	case e := <-sub:
		got = append(got, e)
	default:
		t.Fatal("initial event was not present in the capacity-one subscriber")
	}
	for i := 0; i < 20; i++ {
		c.pollOnce()
		select {
		case e := <-sub:
			got = append(got, e)
		default:
		}
	}
	var turns, toolEvents, toolStarts, modelCalls int
	for _, e := range got {
		switch e.Kind {
		case event.KindTurn:
			turns++
		case event.KindToolCall:
			toolEvents++
			if e.ToolStatus == "running" {
				toolStarts++
			}
		case event.KindModelCall:
			modelCalls++
		}
	}
	if len(got) < 2 || got[1].Kind != event.KindToolCall || got[1].CallID != "call-1" || got[1].ToolStatus != "running" {
		t.Fatalf("first retried assistant row event = %+v, want call-1 start before its second call", got)
	}
	if len(got) != 9 || turns != 2 || toolEvents != 4 || toolStarts != 2 || modelCalls != 3 {
		t.Fatalf("retried %d events (turns=%d tool events=%d tool starts=%d model calls=%d), want all retained row and usage events", len(got), turns, toolEvents, toolStarts, modelCalls)
	}
	// A fresh collector loads the checkpoint written after complete delivery.
	b2 := bus.New(1)
	c2 := NewHermesCollector(b2, time.Second)
	c2.Configured = root
	c2.StatePath = state
	c2.now = func() time.Time { return hermesAt(3600) }
	if n := c2.pollOnce(); n != 0 {
		t.Fatalf("reloaded checkpoint emitted %d events after complete delivery", n)
	}
}

func TestHermesRetriesPendingBatchAfterRestartPastFirstSightWindow(t *testing.T) {
	root, main, _ := hermesFixture(t)
	// Keep a nonzero first-sight checkpoint, with newer rows still to collect.
	hermesExec(t, main, fmt.Sprintf(`UPDATE messages SET timestamp = %f WHERE id = 1`, hermesT0-48*60*60))
	hermesExec(t, main,
		fmt.Sprintf(`INSERT INTO sessions (id, source, model, started_at, input_tokens) VALUES ('s-new', 'cli', 'gpt-5', %f, 20)`, hermesT0+20),
		fmt.Sprintf(`INSERT INTO messages (id, session_id, role, timestamp, token_count) VALUES
			(6, 's-new', 'user', %f, 2), (7, 's-new', 'assistant', %f, 10)`, hermesT0+20, hermesT0+21),
		`INSERT INTO session_model_usage (session_id, model, task, input_tokens, output_tokens, estimated_cost_usd) VALUES
			('s-new', 'gpt-5', 'main', 20, 10, 0.001)`)
	state := filepath.Join(t.TempDir(), "hermes-watermark.json")
	b := bus.New(1)
	sub := b.Subscribe()
	c := NewHermesCollector(b, time.Second)
	c.Configured = root
	c.StatePath = state
	c.now = func() time.Time { return hermesAt(3600) }
	c.pollOnce()
	select {
	case e := <-sub:
		if e.Kind != event.KindToolCall || e.CallID != "call-1" || e.ToolStatus != "running" {
			t.Fatalf("first accepted event = %+v, want call-1 start", e)
		}
	default:
		t.Fatal("first accepted event missing")
	}
	data, err := os.ReadFile(state)
	if err != nil {
		t.Fatalf("read first-sight checkpoint while delivery is pending: %v", err)
	}
	var checkpoint hermesState
	if err := json.Unmarshal(data, &checkpoint); err != nil {
		t.Fatalf("decode first-sight checkpoint: %v", err)
	}
	if checkpoint.DBs[filepath.Join(root, "state.db")] != 1 {
		t.Fatalf("persisted root checkpoint = %d, want first-sight watermark 1", checkpoint.DBs[filepath.Join(root, "state.db")])
	}

	// The source is unchanged, but its rows are now outside first-sight's
	// lookback. Only the persisted watermark can resume this pending batch.
	b2 := bus.New(1)
	sub2 := b2.Subscribe()
	c2 := NewHermesCollector(b2, time.Second)
	c2.Configured = root
	c2.StatePath = state
	c2.now = func() time.Time { return hermesAt(3600 + 3*24*60*60) }
	var retried []event.Event
	for i := 0; i < 20; i++ {
		c2.pollOnce()
		select {
		case e := <-sub2:
			retried = append(retried, e)
		default:
		}
	}
	var turns, toolEvents, modelCalls int
	foundSibling := false
	for _, e := range retried {
		switch e.Kind {
		case event.KindTurn:
			turns++
		case event.KindToolCall:
			toolEvents++
			foundSibling = foundSibling || (e.CallID == "call-2" && e.ToolStatus == "running")
		case event.KindModelCall:
			modelCalls++
		}
	}
	if len(retried) != 8 || turns != 2 || toolEvents != 4 || modelCalls != 2 || !foundSibling {
		t.Fatalf("restarted collector retried %d events (turn=%d tool=%d model=%d sibling=%v), want all rejected row and usage events", len(retried), turns, toolEvents, modelCalls, foundSibling)
	}
}

func TestHermesRetriesExistingSessionUsageDeltaAfterRestart(t *testing.T) {
	root, main, profile := hermesFixture(t)
	state := filepath.Join(t.TempDir(), "hermes-watermark.json")
	b0 := bus.New(64)
	sub0 := b0.Subscribe()
	c0 := NewHermesCollector(b0, time.Second)
	c0.Configured = root
	c0.StatePath = state
	c0.now = func() time.Time { return hermesAt(3600) }
	drainOpenclaw(sub0, c0.pollOnce())

	// Grow usage for a pre-existing session without changing its messages, and
	// add one profile event that can checkpoint while the root usage is pending.
	hermesExec(t, main, `UPDATE session_model_usage SET input_tokens = input_tokens + 200, output_tokens = output_tokens + 30,
		estimated_cost_usd = estimated_cost_usd + 0.001 WHERE task = 'main'`)
	hermesExec(t, profile, fmt.Sprintf(`INSERT INTO messages (session_id, role, content, timestamp, token_count)
		VALUES ('p-1', 'assistant', 'new output', %f, 15)`, hermesT0+12))

	b1 := bus.New(1)
	sub1 := b1.Subscribe()
	b1.Publish(event.Event{Kind: event.KindTurn, SessionID: "capacity-sentinel"})
	c1 := NewHermesCollector(b1, time.Second)
	c1.Configured = root
	c1.StatePath = state
	c1.now = func() time.Time { return hermesAt(3600) }
	c1.pollOnce() // root delta is rejected; the profile event is also pending.
	select {
	case e := <-sub1:
		if e.SessionID != "capacity-sentinel" {
			t.Fatalf("buffered event = %+v, want capacity sentinel", e)
		}
	default:
		t.Fatal("capacity sentinel missing")
	}
	profilePath := filepath.Join(root, "profiles", "work", "state.db")
	if n := c1.pollDB(c1.dbs[profilePath]); n != 1 {
		t.Fatalf("profile pending event accepted %d, want one", n)
	}
	if e := <-sub1; e.SessionID != "p-1" {
		t.Fatalf("profile checkpoint event = %+v, want p-1", e)
	}

	// The profile's successful saveState must not persist the root's mutated
	// working usage baseline while its event batch is still rejected.
	b2 := bus.New(1)
	sub2 := b2.Subscribe()
	c2 := NewHermesCollector(b2, time.Second)
	c2.Configured = root
	c2.StatePath = state
	c2.now = func() time.Time { return hermesAt(3600) }
	if n := c2.pollOnce(); n != 1 {
		t.Fatalf("restarted root usage poll accepted %d events, want one delta", n)
	}
	select {
	case e := <-sub2:
		if e.Kind != event.KindModelCall || e.SessionID != "s-child" || e.TokensIn != 200 || e.TokensOut != 30 {
			t.Fatalf("recovered usage delta = %+v, want s-child +200/+30", e)
		}
	default:
		t.Fatal("restarted collector did not emit the rejected existing-session usage delta")
	}
	if n := c2.pollOnce(); n != 0 {
		t.Fatalf("unchanged usage poll emitted %d duplicate events", n)
	}
	select {
	case e := <-sub2:
		t.Fatalf("unchanged usage poll duplicated event %+v", e)
	default:
	}
}

func TestHermesLoadsLegacyWatermarkWithoutHistoricalUsage(t *testing.T) {
	root, _, _ := hermesFixture(t)
	mainPath := filepath.Join(root, "state.db")
	state := filepath.Join(t.TempDir(), "legacy-watermark.json")
	data, err := json.Marshal(hermesState{DBs: map[string]int64{mainPath: 5}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state, data, 0o600); err != nil {
		t.Fatal(err)
	}
	b := bus.New(4)
	sub := b.Subscribe()
	c := NewHermesCollector(b, time.Second)
	c.Configured = root
	c.StatePath = state
	c.loadState()
	d := c.db(mainPath)
	if !d.started || d.watermark != 5 || len(d.usage) != 0 || len(d.live) != 0 {
		t.Fatalf("legacy checkpoint loaded as %+v", d)
	}
	if n := c.pollDB(d); n != 0 {
		t.Fatalf("legacy watermark emitted %d historical usage events", n)
	}
	select {
	case e := <-sub:
		t.Fatalf("legacy watermark emitted historical event %+v", e)
	default:
	}
}

func TestHermesPersistsZeroDeltaUsageBaseline(t *testing.T) {
	root, _, _ := hermesFixture(t)
	state := filepath.Join(t.TempDir(), "hermes-watermark.json")
	b0 := bus.New(64)
	c0 := NewHermesCollector(b0, time.Second)
	c0.Configured = root
	c0.StatePath = state
	c0.now = func() time.Time { return hermesAt(3600) }
	c0.pollOnce()

	// Load the committed live-session baseline, remove its backing file, then
	// read unchanged SQLite state. A zero-event poll must recreate the checkpoint.
	b1 := bus.New(4)
	c1 := NewHermesCollector(b1, time.Second)
	c1.Configured = root
	c1.StatePath = state
	c1.loadState()
	if err := os.Remove(state); err != nil {
		t.Fatal(err)
	}
	d := c1.db(filepath.Join(root, "state.db"))
	if n := c1.pollDB(d); n != 0 {
		t.Fatalf("unchanged usage baseline emitted %d events", n)
	}
	if _, err := os.Stat(state); err != nil {
		t.Fatalf("zero-delta usage read did not persist its baseline: %v", err)
	}
}

func TestHermesPendingFlushPreservesReadError(t *testing.T) {
	root, _, _ := hermesFixture(t)
	b := bus.New(1)
	sub := b.Subscribe()
	c := NewHermesCollector(b, time.Second)
	d := c.db(filepath.Join(root, "state.db"))
	d.lastErr = "usage query: transient failure"
	d.pending = &hermesPending{
		events: []event.Event{{Kind: event.KindTurn, SessionID: "s-child"}},
		clean:  true, sessions: map[string]hermesSession{},
	}
	if n := c.pollDB(d); n != 1 {
		t.Fatalf("pending flush accepted %d events, want 1", n)
	}
	select {
	case <-sub:
	default:
		t.Fatal("pending event was not delivered")
	}
	if d.lastErr != "usage query: transient failure" {
		t.Fatalf("pending flush cleared read error without a read: %q", d.lastErr)
	}
	if n := c.pollDB(d); n != 0 || d.lastErr != "" {
		t.Fatalf("successful follow-up read = events %d, error %q; want cleared error", n, d.lastErr)
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

func TestHermesStateDirectoryPriority(t *testing.T) {
	getenv := func(key string) string {
		return map[string]string{"HERMES_STATE_DIR": "/state", "HERMES_HOME": "/home"}[key]
	}
	if got := HermesHome("/configured", getenv, "/user"); got != "/configured" {
		t.Fatalf("configured root = %q, want /configured", got)
	}
	if got := HermesHome("", getenv, "/user"); got != "/state" {
		t.Fatalf("state directory = %q, want /state", got)
	}
}

func TestHermesHonoursStateDirectoryEnv(t *testing.T) {
	root, _, _ := hermesFixture(t)
	t.Setenv("HERMES_STATE_DIR", root)
	t.Setenv("HERMES_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	c, sub, _, _ := newTestHermes(t, "")
	if n := c.pollOnce(); n != 9 {
		t.Fatalf("pollOnce via HERMES_STATE_DIR published %d, want 9", n)
	} else {
		drainOpenclaw(sub, n)
	}
	if st := c.Status(); st.Root != root || len(st.DBs) != 2 {
		t.Fatalf("status = %+v, want selected root with 2 databases", st)
	}
}

func TestHermesUsesLoginShellHomeWhenEnvironmentHasNone(t *testing.T) {
	root, _, _ := hermesFixture(t)
	t.Setenv("HERMES_STATE_DIR", "")
	t.Setenv("HERMES_HOME", "")
	t.Setenv("HOME", t.TempDir())
	c, sub, _, _ := newTestHermes(t, "")
	c.LoginEnv = LoginShellEnv("HERMES_STATE_DIR", "HERMES_HOME")
	t.Setenv("SHELL", fakeLoginShell(t, root))
	if n := c.pollOnce(); n != 9 {
		t.Fatalf("pollOnce via the login shell published %d, want 9", n)
	} else {
		drainOpenclaw(sub, n)
	}
	if st := c.Status(); st.Root != root || len(st.DBs) != 2 {
		t.Fatalf("status = %+v, want the login shell's root with 2 databases", st)
	}
	// The daemon's own environment still wins over the login shell.
	other := t.TempDir()
	t.Setenv("HERMES_HOME", other)
	c.pollOnce()
	if st := c.Status(); st.Root != other {
		t.Fatalf("root = %q, want the daemon environment's %q", st.Root, other)
	}
}

func TestHermesProcessStateDiscovery(t *testing.T) {
	root, _, _ := hermesFixture(t)
	emptyEnv := func(string) string { return "" }
	home := t.TempDir()
	exe := filepath.Join(root, "hermes-agent", "venv", "bin", "python3")
	if got := HermesHome("", emptyEnv, home, exe); got != root {
		t.Fatalf("discovered root = %q, want %q", got, root)
	}
	installed := filepath.Join(t.TempDir(), ".hermes")
	if err := os.Symlink(root, installed); err != nil {
		t.Fatal(err)
	}
	if got := HermesHome("", emptyEnv, home, filepath.Join(installed, "bin", "hermes")); got != installed {
		t.Fatalf("discovered .hermes root = %q, want %q", got, installed)
	}
	// Explicit roots stay authoritative even before their database exists.
	configured := filepath.Join(t.TempDir(), "not-created")
	if got := HermesHome(configured, emptyEnv, home, exe); got != configured {
		t.Fatalf("configured root changed to %q", got)
	}
	for _, key := range []string{"HERMES_STATE_DIR", "HERMES_HOME"} {
		getenv := func(k string) string {
			if k == key {
				return "  " + configured + "  "
			}
			return ""
		}
		if got := HermesHome("", getenv, home, exe); got != configured {
			t.Fatalf("%s root changed to %q", key, got)
		}
	}
	// A default home containing only a profile database still takes priority.
	profile := filepath.Join(home, ".hermes", "profiles", "work")
	if err := os.MkdirAll(profile, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profile, "state.db"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := HermesHome("", emptyEnv, home, exe); got != filepath.Join(home, ".hermes") {
		t.Fatalf("default profile root = %q", got)
	}
	// A tagged executable alone does not prove that a state database exists.
	otherHome := t.TempDir()
	if got := HermesHome("", emptyEnv, otherHome, filepath.Join(t.TempDir(), ".hermes", "bin", "hermes")); got != filepath.Join(otherHome, ".hermes") {
		t.Fatalf("nonexistent database selected: %q", got)
	}
}

func TestHermesDiscoversLateProcessStateWithoutEnvironment(t *testing.T) {
	root, _, _ := hermesFixture(t)
	t.Setenv("HERMES_STATE_DIR", "")
	t.Setenv("HERMES_HOME", "")
	t.Setenv("HOME", t.TempDir())
	c, sub, _, _ := newTestHermes(t, "")
	var exes []string
	c.ProcessExes = func() []string { return exes }
	if n := c.pollOnce(); n != 0 {
		t.Fatalf("published %d before Hermes started", n)
	}
	exes = []string{filepath.Join(root, "hermes-agent", "venv", "bin", "python3")}
	if n := c.pollOnce(); n != 9 {
		t.Fatalf("discovered process published %d, want 9", n)
	} else {
		drainOpenclaw(sub, n)
	}
	if st := c.Status(); st.Root != root || len(st.DBs) != 2 {
		t.Fatalf("discovered state = %+v", st)
	}
	if n := c.pollOnce(); n != 0 {
		t.Fatalf("replayed %d events from the discovered database", n)
	}
}

// With no configured root the collector follows $HERMES_HOME.
func TestHermesHonoursHermesHomeEnv(t *testing.T) {
	root, _, _ := hermesFixture(t)
	t.Setenv("HERMES_STATE_DIR", "")
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

// TestHermesFirstSightStartsAtLastDay: a database with no persisted watermark
// starts at the newest message older than 24h — the first poll emits only
// the last day, and s-old (begun before the start) contributes its usage
// totals as a baseline, not as a model call. A persisted watermark is used
// unchanged, even one older than the window.
func TestHermesFirstSightStartsAtLastDay(t *testing.T) {
	root := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(root, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	at := func(ago time.Duration) float64 { return float64(now.Add(-ago).UnixNano()) / 1e9 }
	hermesExec(t, db, hermesDDL, hermesUsageDDL,
		fmt.Sprintf(`INSERT INTO sessions (id, source, model, started_at, input_tokens) VALUES
		 ('s-old', 'cli', 'claude-sonnet-4-5', %f, 900), ('s-new', 'cli', 'claude-sonnet-4-5', %f, 0)`, at(48*time.Hour), at(time.Minute)),
		fmt.Sprintf(`INSERT INTO messages (id, session_id, role, content, timestamp) VALUES
		 (1, 's-old', 'user', 'x', %f), (2, 's-old', 'user', 'x', %f),
		 (3, 's-old', 'user', 'x', %f), (4, 's-new', 'user', 'x', %f)`,
			at(48*time.Hour), at(30*time.Hour), at(2*time.Hour), at(time.Minute)),
		`INSERT INTO session_model_usage (session_id, model, input_tokens, output_tokens, estimated_cost_usd) VALUES
		 ('s-old', 'claude-sonnet-4-5', 900, 90, 0.01)`)

	var logBuf strings.Builder
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	state := filepath.Join(t.TempDir(), "hermes-watermark.json")
	c, sub, _, _ := newTestHermes(t, root)
	c.now = func() time.Time { return now }
	c.StatePath = state
	n := c.pollOnce()
	evs := drainOpenclaw(sub, n)
	if n != 2 || evs[0].Kind != event.KindTurn || !evs[0].TS.Equal(now.Add(-2*time.Hour)) ||
		evs[1].Kind != event.KindTurn || evs[1].SessionID != "s-new" || !evs[1].TS.Equal(now.Add(-time.Minute)) {
		t.Fatalf("first poll = %d events %+v, want the turns at now-2h and now-1m only", n, evs)
	}
	if want := "from message 2 (first sight: last 24h)"; !strings.Contains(logBuf.String(), want) {
		t.Fatalf("log = %q, want %q", logBuf.String(), want)
	}
	if st := c.Status(); st.DBs[0].Watermark != 4 {
		t.Fatalf("watermark = %d, want 4", st.DBs[0].Watermark)
	}

	// A persisted watermark older than the window resumes exactly there.
	if err := os.WriteFile(state, []byte(fmt.Sprintf(`{"dbs":{%q:1}}`, filepath.Join(root, "state.db"))), 0o600); err != nil {
		t.Fatal(err)
	}
	c2, sub2, _, _ := newTestHermes(t, root)
	c2.now = func() time.Time { return now }
	c2.StatePath = state
	n = c2.pollOnce()
	evs = drainOpenclaw(sub2, n)
	var turns int
	for _, e := range evs {
		if e.Kind == event.KindTurn {
			turns++
		}
	}
	if turns != 3 || !evs[0].TS.Equal(now.Add(-30*time.Hour)) {
		t.Fatalf("resumed poll = %+v, want the turns of messages 2, 3 and 4", evs)
	}

	// A persisted watermark of 0 is still a resume, not a first sight: the
	// next poll reads every message from id 0, not just the last 24h.
	if err := os.WriteFile(state, []byte(fmt.Sprintf(`{"dbs":{%q:0}}`, filepath.Join(root, "state.db"))), 0o600); err != nil {
		t.Fatal(err)
	}
	c3, sub3, _, _ := newTestHermes(t, root)
	c3.now = func() time.Time { return now }
	c3.StatePath = state
	n = c3.pollOnce()
	evs = drainOpenclaw(sub3, n)
	turns = 0
	for _, e := range evs {
		if e.Kind == event.KindTurn {
			turns++
		}
	}
	if turns != 4 || !evs[0].TS.Equal(now.Add(-48*time.Hour)) {
		t.Fatalf("resumed-at-zero poll = %+v, want all 4 turns starting at message 1", evs)
	}
}
