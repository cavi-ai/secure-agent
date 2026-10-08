package collect

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// Claude Code transcript trace parsing (~/.claude/projects/<slug>/*.jsonl).
// Each line is one transcript record; assistant records carry model + usage,
// tool_use blocks open a call, tool_result blocks (on user records) close it.
// Content is NEVER carried into events — only tool names, durations, model
// ids and token counts. A transcript line is metadata-only telemetry.

// claudeRecord is the subset of the Claude Code JSONL transcript schema the
// tracer reads. Unknown fields are ignored — the schema evolves, the trace
// degrades to fewer events, never wrong ones.
type claudeRecord struct {
	Type      string `json:"type"`      // assistant | user | ...
	SessionID string `json:"sessionId"` // matches CLAUDE_SESSION_ID the hook sees
	CWD       string `json:"cwd"`
	Timestamp string `json:"timestamp"`
	// isMeta records are harness-injected context (system reminders,
	// command wrappers), never operator prompts. isSidechain records are
	// subagent side conversations. Both must not count as turns: counting
	// them drowns real prompts in noise and understates turn coverage.
	IsMeta      *bool `json:"isMeta"`
	IsSidechain *bool `json:"isSidechain"`
	Message     struct {
		ID      string          `json:"id"` // API message id; repeated on every record of one call
		Model   string          `json:"model"`
		Usage   *claudeUsage    `json:"usage"`
		Content json.RawMessage `json:"content"`
	} `json:"message"`
}

// injected reports whether the record is harness plumbing (meta/sidechain),
// so its text can never read as an operator prompt.
func (r *claudeRecord) injected() bool {
	return (r.IsMeta != nil && *r.IsMeta) || (r.IsSidechain != nil && *r.IsSidechain)
}

// claudeContents decodes a message's content, which Claude writes either as an
// array of blocks (normal) or as a bare JSON string (older/simple user
// records). Returning the string as a text block keeps turn detection honest
// without a second parse path.
func claudeContents(raw json.RawMessage) []claudeContent {
	if len(raw) == 0 {
		return nil
	}
	var blocks []claudeContent
	if json.Unmarshal(raw, &blocks) == nil {
		return blocks
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []claudeContent{{Type: "text", Text: s}}
	}
	return nil
}

type claudeUsage struct {
	InputTokens         int64 `json:"input_tokens"`
	OutputTokens        int64 `json:"output_tokens"`
	CacheCreationTokens int64 `json:"cache_creation_input_tokens"`
	CacheReadTokens     int64 `json:"cache_read_input_tokens"`
}

type claudeContent struct {
	Type      string `json:"type"` // text | tool_use | tool_result
	ID        string `json:"id"`
	Name      string `json:"name"`
	ToolUseID string `json:"tool_use_id"`
	IsError   bool   `json:"is_error"`
	Text      string `json:"text"`
}

// pendingTool is an open tool_use awaiting its tool_result.
type pendingTool struct {
	name string
	ts   time.Time
}

// claudeMsgMemory bounds how many recent message ids a tracer remembers. The
// records of one API call are written together, so a handful suffices; a
// repeat that arrives after eviction (or after a restart) is still folded by
// the store's upsert on (session_id, call_id).
const claudeMsgMemory = 64

// claudeMsg is a model call already emitted for a message id.
type claudeMsg struct {
	ts      time.Time
	in, out int64
}

// ClaudeTracer turns transcript lines into trace events. It is stateful per
// file: tool_use ids pair with tool_results across lines, and the records of
// one API call fold into one model call.
type ClaudeTracer struct {
	pending pendingTools // bounded tool_use id → open call
	// msgs maps a recent message id to the model call emitted for it;
	// msgRing evicts the oldest past claudeMsgMemory.
	msgs      map[string]claudeMsg
	msgRing   [claudeMsgMemory]string
	msgNext   int
	sessionID string // the last record's session id
}

func NewClaudeTracer() *ClaudeTracer {
	return &ClaudeTracer{msgs: map[string]claudeMsg{}}
}

// Session returns the session id of the last transcript record parsed.
func (t *ClaudeTracer) Session() string {
	return t.sessionID
}

// IsClaudeTranscriptPath reports whether a tailed file is a Claude Code
// project transcript (vs the plugin activity log or another harness's log).
func IsClaudeTranscriptPath(path string) bool {
	return strings.Contains(path, "/.claude/projects/")
}

// ParseLine consumes one transcript line and returns zero or more trace
// events plus the record's cwd (for transcript-tier session resolution).
// ok=false means the line is not a Claude transcript record.
func (t *ClaudeTracer) ParseLine(line string) (events []event.Event, cwd string, ok bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "{") || !strings.Contains(trimmed, `"sessionId"`) {
		return nil, "", false
	}
	var rec claudeRecord
	if err := json.Unmarshal([]byte(trimmed), &rec); err != nil || rec.SessionID == "" {
		return nil, "", false
	}
	if rec.Type != "assistant" && rec.Type != "user" {
		return nil, "", false
	}
	if t.sessionID != "" && t.sessionID != rec.SessionID {
		t.pending = pendingTools{}
		t.msgs = map[string]claudeMsg{}
		t.msgRing = [claudeMsgMemory]string{}
		t.msgNext = 0
	}
	t.sessionID = rec.SessionID
	ts := time.Now()
	if rec.Timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, rec.Timestamp); err == nil {
			ts = parsed
		}
	}

	contents := claudeContents(rec.Message.Content)
	events = append(events, t.pending.expire(ts)...)

	switch rec.Type {
	case "assistant":
		if mc, ok := t.modelCall(&rec, ts); ok {
			events = append(events, mc)
		}
		for _, c := range contents {
			if c.Type == "tool_use" && c.ID != "" && c.Name != "" {
				events = append(events, t.pending.add(c.ID, rec.SessionID, pendingTool{name: c.Name, ts: ts})...)
				// One row per call, keyed by the harness's tool_use id: the
				// completion below updates THIS row (store upserts on
				// session_id+call_id), so a call is never a stale "running"
				// row plus a duplicate completion row.
				events = append(events, event.Event{
					Kind: event.KindToolCall, TS: ts, SessionID: rec.SessionID,
					CallID: c.ID, ToolName: c.Name, ToolStatus: "running",
				})
			}
		}
	case "user":
		for _, c := range contents {
			if c.Type != "tool_result" || c.ToolUseID == "" {
				continue
			}
			status := "ok"
			if c.IsError {
				status = "error"
			}
			if e, found := t.pending.completion(c.ToolUseID, rec.SessionID, status, ts); found {
				events = append(events, e)
			}
		}
		// A user record carrying real prompt text is a turn boundary. Tool
		// results, system wrappers, isMeta and isSidechain records are not.
		if rec.injected() {
			break
		}
		for _, c := range contents {
			if c.Type == "tool_result" {
				continue
			}
			if c.Type == "text" && isPromptText(c.Text) {
				events = append(events, event.Event{
					Kind: event.KindTurn, TS: ts, SessionID: rec.SessionID,
				})
				break
			}
		}
	}
	return events, rec.CWD, len(events) > 0
}

// modelCall returns the model call an assistant record bills, or false when it
// bills none. Claude Code writes one record per content block (thinking, text,
// tool_use), each repeating the message id and usage: the call is emitted on
// the message's first record, and again only when a later record carries more
// usage — at the first record's timestamp, so the store's upsert on
// (session_id, call_id) raises the one row to the final counts.
func (t *ClaudeTracer) modelCall(rec *claudeRecord, ts time.Time) (event.Event, bool) {
	m := &rec.Message
	// "<synthetic>" is Claude Code's own zero-usage turn, not a model call.
	if m.Usage == nil || m.Model == "" || m.Model == "<synthetic>" {
		return event.Event{}, false
	}
	in := m.Usage.InputTokens + m.Usage.CacheCreationTokens
	out := m.Usage.OutputTokens
	if m.ID != "" {
		if prev, seen := t.msgs[m.ID]; seen {
			if in <= prev.in && out <= prev.out {
				return event.Event{}, false
			}
			ts, in, out = prev.ts, max(in, prev.in), max(out, prev.out)
		}
		t.rememberMsg(m.ID, claudeMsg{ts: ts, in: in, out: out})
	}
	return event.Event{
		Kind:      event.KindModelCall,
		TS:        ts,
		SessionID: rec.SessionID,
		Model:     m.Model,
		Provider:  "anthropic",
		TokensIn:  in,
		TokensOut: out,
		CostUSD:   ModelCostUSD(m.Model, in, out),
		CallID:    m.ID,
	}, true
}

// rememberMsg records the model call emitted for a message id, evicting the
// oldest id once claudeMsgMemory are held.
func (t *ClaudeTracer) rememberMsg(id string, m claudeMsg) {
	if _, held := t.msgs[id]; !held {
		if old := t.msgRing[t.msgNext]; old != "" {
			delete(t.msgs, old)
		}
		t.msgRing[t.msgNext] = id
		t.msgNext = (t.msgNext + 1) % claudeMsgMemory
	}
	t.msgs[id] = m
}

// isPromptText filters out the harness's own wrapper content so only genuine
// operator prompts count as turns.
func isPromptText(s string) bool {
	t := strings.TrimSpace(s)
	if t == "" {
		return false
	}
	// System-injected wrappers, not user prompts.
	for _, pre := range []string{"<task-notification>", "<system-reminder>", "<command-name>", "<local-command"} {
		if strings.HasPrefix(t, pre) {
			return false
		}
	}
	return true
}
