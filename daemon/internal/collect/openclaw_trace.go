package collect

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// openclaw trace collection.
//
// openclaw writes no transcript the tailers read: its gateway records every
// conversation in a SQLite database, lcm.db, in its state directory —
// conversations (session_id, session_key "agent:<name>:…", active,
// archived_at), messages (role, created_at) and message_parts (part_type,
// tool_call_id, tool_name, step tokens, metadata JSON naming the model or the
// tool call a result answers). This collector polls it the way the opencode
// poller reads opencode.db.
//
// Safety rules, because this is another application's live database:
//   - Opened READ-ONLY (mode=ro, query_only) with a busy timeout; never
//     written, never locked against the gateway.
//   - Watermarked on messages.message_id (monotonic AUTOINCREMENT) and
//     bounded to maxOpenclawMessages per poll; a backlog drains over polls.
//   - Content columns (messages.content, tool input/output, text) are never
//     selected: only ids, roles, tool names, statuses, token counts, model
//     ids and timestamps.
//   - A missing database is a silent no-op; a schema drift logs and
//     degrades to "not covered", never an error loop.
//
// Trace mapping:
//   - conversation session_id → session, harness "openclaw", workspace label
//     "openclaw:<agent>" from the session_key (lcm.db records no cwd); ended
//     when every conversation of that session is inactive or archived.
//   - user message → turn (kind 13).
//   - tool part of an assistant message → tool_call (kind 12, running); its
//     result — a tool-role message whose part metadata names the call id —
//     completes the same call ok or error, with the duration between the two
//     messages' created_at (whole seconds, as lcm.db stores them).
//   - part with step tokens → model_call (kind 14) with step_cost and the
//     model the part metadata names.

const (
	openclawPollInterval = 5 * time.Second
	// maxOpenclawMessages bounds messages read per poll (each carries a few
	// parts); a larger backlog drains over successive polls.
	maxOpenclawMessages = 200
	// maxOpenclawOpenCalls bounds the call-start memory used for durations.
	maxOpenclawOpenCalls = 4096
	// openclawTimeLayout is SQLite's datetime('now') format, UTC.
	openclawTimeLayout = "2006-01-02 15:04:05"
)

// OpenclawCollector polls openclaw's lcm.db for trace events.
type OpenclawCollector struct {
	bus      *bus.Bus
	interval time.Duration

	// Configured is the openclaw_home setting; when set it is the only
	// candidate. ProcessExes, when set, lists the executable paths of running
	// openclaw processes (the tagger's view) for the last-resort lookup.
	Configured  string
	ProcessExes func() []string
	// StatePath, when set, persists the watermark across daemon restarts so
	// history is read once and a restart neither replays nor skips messages.
	StatePath string

	// OnProduce fires after events are published (coverage heartbeat).
	OnProduce func()
	// OnSessionSeen reports a conversation (id, harness, workspace, time)
	// before any of its events are published.
	OnSessionSeen func(sessionID, harness, workspace string, at time.Time)
	// OnSessionEnded reports a conversation openclaw marked inactive or
	// archived.
	OnSessionEnded func(sessionID string, at time.Time)

	dbPath    string // resolved lcm.db; "" until found
	watermark int64  // highest messages.message_id read
	noted     map[string]bool
	ended     map[string]bool
	callStart map[string]time.Time // session\x00call id → call message time
}

// NewOpenclawCollector builds the poller. dbPath, when non-empty, pins the
// database (tests); otherwise it is resolved on each poll until found.
func NewOpenclawCollector(b *bus.Bus, dbPath string, interval time.Duration) *OpenclawCollector {
	if interval <= 0 {
		interval = openclawPollInterval
	}
	return &OpenclawCollector{
		bus: b, dbPath: dbPath, interval: interval,
		noted: map[string]bool{}, ended: map[string]bool{}, callStart: map[string]time.Time{},
	}
}

// OpenclawHome picks openclaw's state directory: the first candidate holding
// lcm.db among $OPENCLAW_STATE_DIR, $OPENCLAW_HOME/.openclaw, ~/.openclaw,
// then the state directory of a running openclaw process — its executable
// path cut at the "/.openclaw/" segment the agent matcher keys on (openclaw
// runs its bundled node from there). A configured path is authoritative.
// "" when no candidate holds lcm.db.
func OpenclawHome(configured string, getenv func(string) string, home string, exePaths []string) string {
	has := func(dir string) bool {
		fi, err := os.Stat(filepath.Join(dir, "lcm.db"))
		return dir != "" && err == nil && !fi.IsDir()
	}
	if configured != "" {
		if has(configured) {
			return configured
		}
		return ""
	}
	var cands []string
	if v := getenv("OPENCLAW_STATE_DIR"); v != "" {
		cands = append(cands, v)
	}
	if v := getenv("OPENCLAW_HOME"); v != "" {
		cands = append(cands, filepath.Join(v, ".openclaw"))
	}
	if home != "" {
		cands = append(cands, filepath.Join(home, ".openclaw"))
	}
	for _, exe := range exePaths {
		if i := strings.Index(exe, "/.openclaw/"); i >= 0 {
			cands = append(cands, exe[:i+len("/.openclaw")])
		}
	}
	for _, c := range cands {
		if has(c) {
			return c
		}
	}
	return ""
}

// resolve finds lcm.db once; until then every poll retries (openclaw may
// start after the daemon).
func (c *OpenclawCollector) resolve() bool {
	if c.dbPath != "" {
		return true
	}
	var exes []string
	if c.ProcessExes != nil {
		exes = c.ProcessExes()
	}
	home, _ := os.UserHomeDir()
	dir := OpenclawHome(c.Configured, os.Getenv, home, exes)
	if dir == "" {
		return false
	}
	c.dbPath = filepath.Join(dir, "lcm.db")
	c.loadState()
	log.Printf("openclaw: polling %s from message %d", c.dbPath, c.watermark)
	return true
}

// Run polls until ctx is done. Never errors the supervisor.
func (c *OpenclawCollector) Run(ctx context.Context) error {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		if n := c.pollOnce(); n > 0 && c.OnProduce != nil {
			c.OnProduce()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (c *OpenclawCollector) openReadOnly() (*sql.DB, error) {
	if _, err := os.Stat(c.dbPath); err != nil {
		return nil, err
	}
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=busy_timeout(2000)&_pragma=query_only(true)",
		url.PathEscape(c.dbPath))
	return sql.Open("sqlite", dsn)
}

// openclawRow is one message × part row of a poll. No content column.
type openclawRow struct {
	msgID                         int64
	role, created, sessionID, key string
	partType, callID, toolName    string
	toolStatus                    string
	toolFailed                    bool
	stepCost                      float64
	tokIn, tokOut                 int64
	resultCallID, resultTool      string
	resultError                   bool
	modelID, modelProvider        string
}

// openclawMessagesQuery reads the next bounded batch of messages with their
// parts. json_valid guards json_extract: one malformed metadata value must
// not fail the batch.
const openclawMessagesQuery = `
SELECT m.message_id, m.role, m.created_at, c.session_id, COALESCE(c.session_key, ''),
       COALESCE(p.part_type, ''), COALESCE(p.tool_call_id, ''), COALESCE(p.tool_name, ''),
       COALESCE(p.tool_status, ''), COALESCE(p.tool_error, '') != '',
       COALESCE(p.step_cost, 0), COALESCE(p.step_tokens_in, 0), COALESCE(p.step_tokens_out, 0),
       CASE WHEN json_valid(p.metadata) THEN COALESCE(json_extract(p.metadata, '$.toolCallId'), '') ELSE '' END,
       CASE WHEN json_valid(p.metadata) THEN COALESCE(json_extract(p.metadata, '$.toolName'), '') ELSE '' END,
       CASE WHEN json_valid(p.metadata) THEN COALESCE(json_extract(p.metadata, '$.isError'), 0) = 1 ELSE 0 END,
       CASE WHEN json_valid(p.metadata) THEN COALESCE(json_extract(p.metadata, '$.modelId'), '') ELSE '' END,
       CASE WHEN json_valid(p.metadata) THEN COALESCE(json_extract(p.metadata, '$.modelProvider'), '') ELSE '' END
FROM messages m
JOIN conversations c ON c.conversation_id = m.conversation_id
LEFT JOIN message_parts p ON p.message_id = m.message_id
WHERE m.message_id IN (SELECT message_id FROM messages WHERE message_id > ? ORDER BY message_id LIMIT ?)
ORDER BY m.message_id, p.ordinal`

// openclawStateQuery reports, per session, whether any conversation is still
// live, when the last one was archived or updated, and its newest message.
const openclawStateQuery = `
SELECT c.session_id,
       MAX(c.active = 1 AND c.archived_at IS NULL),
       MAX(COALESCE(c.archived_at, c.updated_at)),
       MAX(COALESCE((SELECT MAX(m.message_id) FROM messages m WHERE m.conversation_id = c.conversation_id), 0))
FROM conversations c
GROUP BY c.session_id`

// pollOnce reads messages past the watermark, publishes their events, ends
// conversations openclaw closed, and returns how many events were published.
func (c *OpenclawCollector) pollOnce() int {
	if !c.resolve() {
		return 0
	}
	db, err := c.openReadOnly()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("openclaw: cannot read %s: %v", c.dbPath, err)
		}
		return 0
	}
	defer db.Close()

	published, ok := c.readMessages(db)
	if ok {
		c.endClosed(db)
	}
	return published
}

func (c *OpenclawCollector) readMessages(db *sql.DB) (int, bool) {
	rows, err := db.Query(openclawMessagesQuery, c.watermark, maxOpenclawMessages)
	if err != nil {
		log.Printf("openclaw: query failed (schema drift?): %v", err)
		return 0, false
	}
	defer rows.Close()

	published := 0
	maxSeen := c.watermark
	var lastMsg int64
	for rows.Next() {
		var r openclawRow
		if err := rows.Scan(&r.msgID, &r.role, &r.created, &r.sessionID, &r.key,
			&r.partType, &r.callID, &r.toolName, &r.toolStatus, &r.toolFailed,
			&r.stepCost, &r.tokIn, &r.tokOut,
			&r.resultCallID, &r.resultTool, &r.resultError, &r.modelID, &r.modelProvider); err != nil {
			continue
		}
		if r.msgID > maxSeen {
			maxSeen = r.msgID
		}
		if r.sessionID == "" {
			continue
		}
		ts := parseOpenclawTime(r.created)
		if !c.noted[r.sessionID] {
			c.noted[r.sessionID] = true
			if c.OnSessionSeen != nil {
				c.OnSessionSeen(r.sessionID, "openclaw", OpenclawWorkspaceLabel(r.key), ts)
			}
		}
		first := r.msgID != lastMsg
		lastMsg = r.msgID
		for _, e := range c.rowEvents(r, ts, first) {
			c.bus.Publish(e)
			published++
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("openclaw: cursor error (partial poll): %v", err)
	}
	if maxSeen > c.watermark {
		c.watermark = maxSeen
		c.saveState()
	}
	return published, true
}

// rowEvents maps one message × part row to trace events. first is true for
// the message's first row (the turn is emitted once per message).
func (c *OpenclawCollector) rowEvents(r openclawRow, ts time.Time, first bool) []event.Event {
	var out []event.Event
	if first && r.role == "user" {
		out = append(out, event.Event{Kind: event.KindTurn, TS: ts, SessionID: r.sessionID})
	}
	switch {
	case r.partType == "tool" && r.toolName != "":
		status := openclawToolStatus(r.toolStatus, r.toolFailed)
		if r.callID != "" && status == "running" {
			if len(c.callStart) >= maxOpenclawOpenCalls {
				c.callStart = map[string]time.Time{}
			}
			c.callStart[r.sessionID+"\x00"+r.callID] = ts
		}
		out = append(out, event.Event{
			Kind: event.KindToolCall, TS: ts, SessionID: r.sessionID,
			CallID: r.callID, ToolName: r.toolName, ToolStatus: status,
		})
	case r.role == "tool" && r.resultCallID != "":
		status := "ok"
		if r.resultError {
			status = "error"
		}
		start := ts
		var durMs int64
		key := r.sessionID + "\x00" + r.resultCallID
		if at, ok := c.callStart[key]; ok {
			delete(c.callStart, key)
			if !ts.Before(at) {
				start, durMs = at, ts.Sub(at).Milliseconds()
			}
		}
		out = append(out, event.Event{
			Kind: event.KindToolCall, TS: start, SessionID: r.sessionID,
			CallID: r.resultCallID, ToolName: r.resultTool, ToolStatus: status, DurationMs: durMs,
		})
	}
	if r.tokIn > 0 || r.tokOut > 0 {
		cost := r.stepCost
		if cost == 0 && r.modelID != "" {
			cost = ModelCostUSD(r.modelID, r.tokIn, r.tokOut)
		}
		out = append(out, event.Event{
			Kind: event.KindModelCall, TS: ts, SessionID: r.sessionID,
			Model: r.modelID, Provider: r.modelProvider,
			TokensIn: r.tokIn, TokensOut: r.tokOut, CostUSD: cost,
		})
	}
	return out
}

// endClosed ends every session whose conversations openclaw has all marked
// inactive or archived, once all of its messages have been read (so its
// session exists before it ends). Once per session per daemon run.
func (c *OpenclawCollector) endClosed(db *sql.DB) {
	if c.OnSessionEnded == nil {
		return
	}
	rows, err := db.Query(openclawStateQuery)
	if err != nil {
		log.Printf("openclaw: conversation state query failed: %v", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var sid string
		var live bool
		var at sql.NullString
		var lastMsg int64
		if rows.Scan(&sid, &live, &at, &lastMsg) != nil || sid == "" {
			continue
		}
		if live || c.ended[sid] || lastMsg > c.watermark {
			continue
		}
		c.ended[sid] = true
		c.OnSessionEnded(sid, parseOpenclawTime(at.String))
	}
}

// OpenclawWorkspaceLabel names a conversation's workspace from its
// session_key ("agent:<name>:…" → "openclaw:<name>"). lcm.db records no cwd.
func OpenclawWorkspaceLabel(sessionKey string) string {
	parts := strings.SplitN(sessionKey, ":", 3)
	if len(parts) >= 2 && parts[0] == "agent" && parts[1] != "" {
		return "openclaw:" + parts[1]
	}
	return "openclaw"
}

// openclawToolStatus maps openclaw's tool status words to ok | error |
// running. An unset status is a call still waiting for its result.
func openclawToolStatus(status string, failed bool) string {
	if failed {
		return "error"
	}
	switch strings.ToLower(status) {
	case "completed", "complete", "success", "succeeded", "ok", "done":
		return "ok"
	case "error", "failed", "failure", "cancelled", "canceled", "aborted":
		return "error"
	}
	return "running"
}

// parseOpenclawTime reads lcm.db's UTC "YYYY-MM-DD HH:MM:SS" (RFC 3339
// accepted too); an unreadable value is "now" rather than year 1.
func parseOpenclawTime(s string) time.Time {
	if t, err := time.ParseInLocation(openclawTimeLayout, s, time.UTC); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	return time.Now()
}

// openclawState is the persisted watermark, tied to the database it counts.
type openclawState struct {
	DB        string `json:"db"`
	MessageID int64  `json:"message_id"`
}

func (c *OpenclawCollector) loadState() {
	if c.StatePath == "" {
		return
	}
	data, err := os.ReadFile(c.StatePath)
	if err != nil {
		return
	}
	var st openclawState
	if json.Unmarshal(data, &st) == nil && st.DB == c.dbPath && st.MessageID > 0 {
		c.watermark = st.MessageID
	}
}

func (c *OpenclawCollector) saveState() {
	if c.StatePath == "" {
		return
	}
	data, err := json.Marshal(openclawState{DB: c.dbPath, MessageID: c.watermark})
	if err != nil {
		return
	}
	tmp := c.StatePath + ".tmp"
	if os.WriteFile(tmp, data, 0o600) == nil {
		_ = os.Rename(tmp, c.StatePath)
	}
}
