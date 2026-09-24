package collect

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// openclawDDL is lcm.db's schema as openclaw creates it (the columns the
// collector reads, plus the content columns it must never carry).
const openclawDDL = `
CREATE TABLE conversations (
  conversation_id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL, session_key TEXT,
  active INTEGER NOT NULL DEFAULT 1, archived_at TEXT, title TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE messages (
  message_id INTEGER PRIMARY KEY AUTOINCREMENT,
  conversation_id INTEGER NOT NULL, seq INTEGER NOT NULL,
  role TEXT NOT NULL, content TEXT NOT NULL, token_count INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  transcript_entry_id TEXT, stable_event_key TEXT);
CREATE TABLE message_parts (
  part_id TEXT PRIMARY KEY, message_id INTEGER NOT NULL, session_id TEXT NOT NULL,
  part_type TEXT NOT NULL, ordinal INTEGER NOT NULL, text_content TEXT,
  tool_call_id TEXT, tool_name TEXT, tool_status TEXT, tool_input TEXT, tool_output TEXT, tool_error TEXT,
  subtask_agent TEXT, step_cost REAL, step_tokens_in INTEGER, step_tokens_out INTEGER, metadata TEXT);`

const openclawSecret = "SECRET-CONTENT-never-in-an-event"

// openclawFixture writes an lcm.db with two conversations: sigmund's cron run
// (a user turn, two tool calls — one ok after 3s, one failed — and a step
// with tokens) and marco's main session (one user turn).
func openclawFixture(t *testing.T) (dir string, db *sql.DB) {
	t.Helper()
	dir = t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "lcm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	stmts := []string{openclawDDL,
		`INSERT INTO conversations (session_id, session_key, active, created_at, updated_at) VALUES
		 ('s-sig', 'agent:sigmund:cron:7:run:9', 1, '2026-09-23 07:00:00', '2026-09-23 07:00:10'),
		 ('s-mar', 'agent:marco:main', 1, '2026-09-23 07:01:00', '2026-09-23 07:01:00')`,
		fmt.Sprintf(`INSERT INTO messages (message_id, conversation_id, seq, role, content, token_count, created_at) VALUES
		 (1, 1, 1, 'user', '%[1]s', 5, '2026-09-23 07:00:00'),
		 (2, 1, 2, 'assistant', '%[1]s', 5, '2026-09-23 07:00:01'),
		 (3, 1, 3, 'tool', '%[1]s', 5, '2026-09-23 07:00:04'),
		 (4, 1, 4, 'assistant', '%[1]s', 5, '2026-09-23 07:00:05'),
		 (5, 1, 5, 'tool', '%[1]s', 5, '2026-09-23 07:00:05'),
		 (6, 2, 1, 'user', '%[1]s', 5, '2026-09-23 07:01:00')`, openclawSecret),
		fmt.Sprintf(`INSERT INTO message_parts (part_id, message_id, session_id, part_type, ordinal, text_content, tool_call_id, tool_name, tool_status, tool_input, step_cost, step_tokens_in, step_tokens_out, metadata) VALUES
		 ('p1', 1, 'x', 'text', 0, '%[1]s', NULL, NULL, NULL, NULL, NULL, NULL, NULL, '{"originalRole":"user"}'),
		 ('p2', 2, 'x', 'tool', 0, NULL, 'call-1', 'exec', NULL, '%[1]s', NULL, NULL, NULL, '{"modelId":"gpt-5.5","modelProvider":"openai"}'),
		 ('p3', 2, 'x', 'step_finish', 1, NULL, NULL, NULL, NULL, NULL, 0.012, 1500, 40, '{"modelId":"gpt-5.5","modelProvider":"openai"}'),
		 ('p4', 3, 'x', 'text', 0, '%[1]s', NULL, NULL, NULL, NULL, NULL, NULL, NULL, '{"toolCallId":"call-1","toolName":"exec","isError":0,"raw":"%[1]s"}'),
		 ('p5', 4, 'x', 'tool', 0, NULL, 'call-2', 'read', NULL, '%[1]s', NULL, NULL, NULL, 'not json'),
		 ('p6', 5, 'x', 'text', 0, '%[1]s', NULL, NULL, NULL, NULL, NULL, NULL, NULL, '{"toolCallId":"call-2","toolName":"read","isError":1}'),
		 ('p7', 6, 'x', 'text', 0, '%[1]s', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)`, openclawSecret),
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	return dir, db
}

type openclawSighting struct{ id, harness, workspace string }

func newTestOpenclaw(t *testing.T, dir string) (*OpenclawCollector, <-chan event.Event, *[]openclawSighting, *[]string) {
	t.Helper()
	b := bus.New(64)
	sub := b.Subscribe()
	c := NewOpenclawCollector(b, filepath.Join(dir, "lcm.db"), time.Second)
	// The fixture's messages are an hour old: all inside the first-sight window.
	c.now = func() time.Time { return time.Date(2026, 9, 23, 8, 0, 0, 0, time.UTC) }
	var seen []openclawSighting
	var ended []string
	c.OnSessionSeen = func(id, harness, ws string, _ time.Time) {
		seen = append(seen, openclawSighting{id, harness, ws})
	}
	c.OnSessionEnded = func(id string, _ time.Time) { ended = append(ended, id) }
	return c, sub, &seen, &ended
}

func drainOpenclaw(sub <-chan event.Event, n int) []event.Event {
	out := make([]event.Event, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, <-sub)
	}
	return out
}

func TestOpenclawPollEmitsTrace(t *testing.T) {
	dir, _ := openclawFixture(t)
	c, sub, seen, _ := newTestOpenclaw(t, dir)

	n := c.pollOnce()
	if n != 7 {
		t.Fatalf("pollOnce published %d events, want 7 (2 turns, 4 tool rows, 1 model call)", n)
	}
	evs := drainOpenclaw(sub, n)

	wantSeen := []openclawSighting{{"s-sig", "openclaw", "openclaw:sigmund"}, {"s-mar", "openclaw", "openclaw:marco"}}
	if fmt.Sprint(*seen) != fmt.Sprint(wantSeen) {
		t.Fatalf("sessions noted = %+v, want %+v", *seen, wantSeen)
	}
	var turns []string
	calls := map[string]event.Event{}
	var model *event.Event
	for i, e := range evs {
		if strings.Contains(fmt.Sprintf("%+v", e), openclawSecret) {
			t.Fatalf("event carries content: %+v", e)
		}
		switch e.Kind {
		case event.KindTurn:
			turns = append(turns, e.SessionID)
		case event.KindToolCall:
			calls[e.CallID+"/"+e.ToolStatus] = e
		case event.KindModelCall:
			model = &evs[i]
		}
	}
	if fmt.Sprint(turns) != "[s-sig s-mar]" {
		t.Fatalf("turns = %v, want one per user message", turns)
	}
	start := time.Date(2026, 9, 23, 7, 0, 1, 0, time.UTC)
	if e, ok := calls["call-1/running"]; !ok || e.ToolName != "exec" || e.SessionID != "s-sig" || !e.TS.Equal(start) {
		t.Fatalf("call-1 start = %+v (ok=%v)", e, ok)
	}
	if e, ok := calls["call-1/ok"]; !ok || e.ToolName != "exec" || e.DurationMs != 3000 || !e.TS.Equal(start) {
		t.Fatalf("call-1 completion = %+v (ok=%v), want ok in 3000ms", e, ok)
	}
	if e, ok := calls["call-2/error"]; !ok || e.ToolName != "read" || e.DurationMs != 0 {
		t.Fatalf("call-2 completion = %+v (ok=%v), want error", e, ok)
	}
	if model == nil || model.TokensIn != 1500 || model.TokensOut != 40 || model.CostUSD != 0.012 ||
		model.Model != "gpt-5.5" || model.Provider != "openai" || model.SessionID != "s-sig" {
		t.Fatalf("model call = %+v", model)
	}
	if c.watermark != 6 {
		t.Fatalf("watermark = %d, want 6", c.watermark)
	}

	// A second poll over an unchanged database emits nothing new.
	if n := c.pollOnce(); n != 0 {
		t.Fatalf("second poll published %d, want 0", n)
	}
}

func TestOpenclawEndsClosedConversation(t *testing.T) {
	dir, db := openclawFixture(t)
	c, sub, _, ended := newTestOpenclaw(t, dir)
	drainOpenclaw(sub, c.pollOnce())
	if len(*ended) != 0 {
		t.Fatalf("ended = %v while every conversation is active", *ended)
	}
	if _, err := db.Exec(`UPDATE conversations SET active = 0 WHERE session_id = 's-mar'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE conversations SET archived_at = '2026-09-23 08:00:00' WHERE session_id = 's-sig'`); err != nil {
		t.Fatal(err)
	}
	c.pollOnce()
	c.pollOnce()
	if fmt.Sprint(*ended) != "[s-mar s-sig]" && fmt.Sprint(*ended) != "[s-sig s-mar]" {
		t.Fatalf("ended = %v, want s-mar and s-sig once each", *ended)
	}
}

func TestOpenclawWatermarkPersists(t *testing.T) {
	dir, db := openclawFixture(t)
	state := filepath.Join(t.TempDir(), "openclaw-watermark.json")
	c, sub, _, _ := newTestOpenclaw(t, dir)
	c.StatePath = state
	c.loadState()
	drainOpenclaw(sub, c.pollOnce())

	// A restarted collector resumes at the persisted watermark: only the new
	// message is read.
	if _, err := db.Exec(`INSERT INTO messages (message_id, conversation_id, seq, role, content, token_count, created_at)
		VALUES (7, 2, 2, 'user', 'x', 1, '2026-09-23 07:02:00')`); err != nil {
		t.Fatal(err)
	}
	c2, sub2, _, _ := newTestOpenclaw(t, dir)
	c2.StatePath = state
	c2.loadState()
	if n := c2.pollOnce(); n != 1 {
		t.Fatalf("restarted poll published %d, want 1 (the new turn)", n)
	}
	if e := <-sub2; e.Kind != event.KindTurn || e.SessionID != "s-mar" {
		t.Fatalf("event = %+v", e)
	}
}

func TestOpenclawMissingDatabaseIsSilentNoop(t *testing.T) {
	c := NewOpenclawCollector(bus.New(4), filepath.Join(t.TempDir(), "lcm.db"), time.Second)
	if n := c.pollOnce(); n != 0 {
		t.Fatalf("missing db published %d", n)
	}
	unresolved := NewOpenclawCollector(bus.New(4), "", time.Second)
	unresolved.Configured = filepath.Join(t.TempDir(), "absent")
	if n := unresolved.pollOnce(); n != 0 || unresolved.dbPath != "" {
		t.Fatalf("unresolved collector published %d, path %q", n, unresolved.dbPath)
	}
}

func TestOpenclawHomeResolution(t *testing.T) {
	root := t.TempDir()
	mk := func(dir string) string {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "lcm.db"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	vol := mk(filepath.Join(root, "Vol", ".openclaw"))
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	none := env(nil)
	home := filepath.Join(root, "home")

	if got := OpenclawHome(vol, none, home, nil); got != vol {
		t.Fatalf("configured = %q, want %q", got, vol)
	}
	if got := OpenclawHome(filepath.Join(root, "nope"), env(map[string]string{"OPENCLAW_STATE_DIR": vol}), home, nil); got != "" {
		t.Fatalf("a configured path without lcm.db must not fall through: %q", got)
	}
	if got := OpenclawHome("", env(map[string]string{"OPENCLAW_STATE_DIR": vol}), home, nil); got != vol {
		t.Fatalf("OPENCLAW_STATE_DIR = %q, want %q", got, vol)
	}
	if got := OpenclawHome("", env(map[string]string{"OPENCLAW_HOME": filepath.Join(root, "Vol")}), home, nil); got != vol {
		t.Fatalf("OPENCLAW_HOME = %q, want %q", got, vol)
	}
	exe := filepath.Join(vol, "node-v24.16.0", "bin", "node")
	if got := OpenclawHome("", none, home, []string{"/usr/bin/true", exe}); got != vol {
		t.Fatalf("process exe = %q, want %q", got, vol)
	}
	h := mk(filepath.Join(home, ".openclaw"))
	if got := OpenclawHome("", none, home, []string{exe}); got != h {
		t.Fatalf("~/.openclaw = %q, want it before the process lookup %q", got, h)
	}
	if got := OpenclawHome("", none, filepath.Join(root, "empty"), nil); got != "" {
		t.Fatalf("no candidate = %q, want empty", got)
	}
}

func TestOpenclawWorkspaceLabel(t *testing.T) {
	for key, want := range map[string]string{
		"agent:sigmund:cron:1:run:2": "openclaw:sigmund",
		"agent:marco":                "openclaw:marco",
		"":                           "openclaw",
		"cron:1":                     "openclaw",
	} {
		if got := OpenclawWorkspaceLabel(key); got != want {
			t.Fatalf("label(%q) = %q, want %q", key, got, want)
		}
	}
}

// TestOpenclawFirstSightStartsAtLastDay: with no persisted watermark the first
// poll starts at the newest message older than 24h; a persisted watermark
// older than the window resumes exactly there.
func TestOpenclawFirstSightStartsAtLastDay(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "lcm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	at := func(ago time.Duration) string { return now.Add(-ago).Format(openclawTimeLayout) }
	stmts := []string{openclawDDL,
		`INSERT INTO conversations (session_id, session_key) VALUES ('s-1', 'agent:marco:main')`,
		fmt.Sprintf(`INSERT INTO messages (message_id, conversation_id, seq, role, content, token_count, created_at) VALUES
		 (1, 1, 1, 'user', 'x', 1, '%s'), (2, 1, 2, 'user', 'x', 1, '%s'),
		 (3, 1, 3, 'user', 'x', 1, '%s'), (4, 1, 4, 'user', 'x', 1, '%s')`,
			at(48*time.Hour), at(30*time.Hour), at(2*time.Hour), at(time.Minute)),
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	c, sub, _, _ := newTestOpenclaw(t, dir)
	c.now = func() time.Time { return now }
	n := c.pollOnce()
	evs := drainOpenclaw(sub, n)
	if n != 2 || !evs[0].TS.Equal(now.Add(-2*time.Hour)) || !evs[1].TS.Equal(now.Add(-time.Minute)) {
		t.Fatalf("first poll = %d events %+v, want the turns at now-2h and now-1m only", n, evs)
	}

	state := filepath.Join(t.TempDir(), "openclaw-watermark.json")
	if err := os.WriteFile(state, []byte(fmt.Sprintf(`{"db":%q,"message_id":1}`, filepath.Join(dir, "lcm.db"))), 0o600); err != nil {
		t.Fatal(err)
	}
	c2, sub2, _, _ := newTestOpenclaw(t, dir)
	c2.now = func() time.Time { return now }
	c2.StatePath = state
	c2.loadState()
	n = c2.pollOnce()
	evs = drainOpenclaw(sub2, n)
	if n != 3 || !evs[0].TS.Equal(now.Add(-30*time.Hour)) {
		t.Fatalf("resumed poll = %d events %+v, want the turns of messages 2, 3 and 4", n, evs)
	}
}
