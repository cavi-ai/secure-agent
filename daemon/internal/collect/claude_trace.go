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

// ClaudeTracer turns transcript lines into trace events. It is stateful per
// file: tool_use ids pair with tool_results across lines.
type ClaudeTracer struct {
	pending map[string]pendingTool // tool_use id → open call
}

func NewClaudeTracer() *ClaudeTracer {
	return &ClaudeTracer{pending: map[string]pendingTool{}}
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
	ts := time.Now()
	if rec.Timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, rec.Timestamp); err == nil {
			ts = parsed
		}
	}

	contents := claudeContents(rec.Message.Content)

	switch rec.Type {
	case "assistant":
		if rec.Message.Usage != nil && rec.Message.Model != "" {
			u := rec.Message.Usage
			in := u.InputTokens + u.CacheCreationTokens
			events = append(events, event.Event{
				Kind:      event.KindModelCall,
				TS:        ts,
				SessionID: rec.SessionID,
				Model:     rec.Message.Model,
				TokensIn:  in,
				TokensOut: u.OutputTokens,
				CostUSD:   ModelCostUSD(rec.Message.Model, in, u.OutputTokens),
			})
		}
		for _, c := range contents {
			if c.Type == "tool_use" && c.ID != "" && c.Name != "" {
				t.pending[c.ID] = pendingTool{name: c.Name, ts: ts}
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
			p, found := t.pending[c.ToolUseID]
			if !found {
				continue
			}
			delete(t.pending, c.ToolUseID)
			status := "ok"
			if c.IsError {
				status = "error"
			}
			events = append(events, event.Event{
				Kind: event.KindToolCall, TS: p.ts, SessionID: rec.SessionID,
				CallID: c.ToolUseID, ToolName: p.name, ToolStatus: status,
				DurationMs: ts.Sub(p.ts).Milliseconds(),
			})
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
