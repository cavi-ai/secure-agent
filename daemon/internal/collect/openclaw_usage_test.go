package collect

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// openclawAgentFixture writes agents/ember/agent/openclaw-agent.sqlite beside
// lcm.db: one assistant event with usage on s-sig, a user event, a
// compressed assistant event and one carrying content but no usage.
func openclawAgentFixture(t *testing.T, dir string) *sql.DB {
	t.Helper()
	p := filepath.Join(dir, "agents", "ember", "agent", openclawAgentDB)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	at := func(sec int) int64 { return time.Date(2026, 9, 23, 7, 0, sec, 0, time.UTC).UnixMilli() }
	usage := fmt.Sprintf(`{"type":"message","message":{"role":"assistant","model":"gpt-5.5","provider":"openai","content":[{"type":"text","text":"%s"}],"usage":{"input":1200,"output":30,"cacheRead":9000,"cacheWrite":100,"totalTokens":10330,"cost":{"total":0.004}}}}`, openclawSecret)
	stmts := []string{
		`CREATE TABLE transcript_events (session_id TEXT NOT NULL, seq INTEGER NOT NULL, event_json TEXT,
		  created_at INTEGER NOT NULL, event_zstd BLOB, message_role TEXT, PRIMARY KEY (session_id, seq))`,
		fmt.Sprintf(`INSERT INTO transcript_events (session_id, seq, event_json, created_at, message_role) VALUES
		  ('s-sig', 1, '{"type":"message","message":{"role":"user","content":"%[1]s"}}', %[2]d, 'user'),
		  ('s-sig', 2, '%[3]s', %[4]d, 'assistant'),
		  ('s-sig', 4, '{"type":"message","message":{"role":"assistant","content":"%[1]s"}}', %[5]d, 'assistant')`,
			openclawSecret, at(0), usage, at(2), at(6)),
		fmt.Sprintf(`INSERT INTO transcript_events (session_id, seq, event_json, created_at, event_zstd, message_role) VALUES
		  ('s-sig', 3, NULL, %d, x'28b52ffd', 'assistant')`, at(4)),
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func TestOpenclawUsageBecomesModelCalls(t *testing.T) {
	dir, _ := openclawFixture(t)
	agent := openclawAgentFixture(t, dir)
	state := filepath.Join(t.TempDir(), "openclaw-watermark.json")
	c, sub, seen, _ := newTestOpenclaw(t, dir)
	c.StatePath = state
	c.loadState()

	// lcm.db's 7 events lose its step-token model call once an agent
	// database answers; the agent database adds its one usage row.
	n := c.pollOnce()
	if n != 7 {
		t.Fatalf("pollOnce published %d events, want 7 (6 from lcm.db, 1 usage model call)", n)
	}
	var models []event.Event
	for _, e := range drainOpenclaw(sub, n) {
		if strings.Contains(fmt.Sprintf("%+v", e), openclawSecret) {
			t.Fatalf("event carries content: %+v", e)
		}
		if e.Kind == event.KindModelCall {
			models = append(models, e)
		}
	}
	if len(models) != 1 {
		t.Fatalf("model calls = %+v, want one (usage only)", models)
	}
	m := models[0]
	if m.SessionID != "s-sig" || m.Model != "gpt-5.5" || m.Provider != "openai" ||
		m.TokensIn != 1300 || m.TokensOut != 30 || m.CostUSD != 0.004 ||
		!m.TS.Equal(time.Date(2026, 9, 23, 7, 0, 2, 0, time.UTC)) {
		t.Fatalf("model call = %+v", m)
	}
	if len(*seen) == 0 || (*seen)[0] != (openclawSighting{"s-sig", "openclaw", "openclaw:ember"}) {
		t.Fatalf("sessions noted = %+v, want s-sig first from the agent database", *seen)
	}
	if n := c.pollOnce(); n != 0 {
		t.Fatalf("second poll published %d, want 0", n)
	}

	// A restarted collector resumes at the persisted watermark: only the new
	// usage row is read.
	at := time.Date(2026, 9, 23, 7, 30, 0, 0, time.UTC).UnixMilli()
	if _, err := agent.Exec(`INSERT INTO transcript_events (session_id, seq, event_json, created_at, message_role) VALUES
		('s-sig', 5, '{"message":{"role":"assistant","model":"gpt-5.5","usage":{"input":10,"output":5}}}', ?, 'assistant')`, at); err != nil {
		t.Fatal(err)
	}
	c2, sub2, _, _ := newTestOpenclaw(t, dir)
	c2.StatePath = state
	c2.loadState()
	if n := c2.pollOnce(); n != 1 {
		t.Fatalf("restarted poll published %d, want 1 (the new usage row)", n)
	}
	if e := <-sub2; e.Kind != event.KindModelCall || e.TokensIn != 10 || e.TokensOut != 5 {
		t.Fatalf("event = %+v", e)
	}
}

// Without an agent transcript database, lcm.db's step tokens stay the model
// calls (older openclaw releases).
func TestOpenclawStepTokensWithoutAgentDatabase(t *testing.T) {
	dir, _ := openclawFixture(t)
	c, sub, _, _ := newTestOpenclaw(t, dir)
	models := 0
	for _, e := range drainOpenclaw(sub, c.pollOnce()) {
		if e.Kind == event.KindModelCall {
			models++
		}
	}
	if models != 1 || c.usageActive {
		t.Fatalf("model calls = %d, usageActive = %v; want 1 from step tokens", models, c.usageActive)
	}
}
