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
	Message   struct {
		Model   string            `json:"model"`
		Usage   *claudeUsage      `json:"usage"`
		Content []json.RawMessage `json:"content"`
	} `json:"message"`
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

// Pricing per 1M tokens (USD), Anthropic list prices. Cost is approximate by
// design: cache-read discounts and tier pricing are not modeled; unknown
// models cost 0 rather than a fabricated number. Operators can refine via
// config later — the tokens are the durable fact, cost is derived.
var modelPricePerMillion = map[string][2]float64{ // [input, output]
	"claude-opus-4-1":   {15, 75},
	"claude-opus-4":     {15, 75},
	"claude-sonnet-4-5": {3, 15},
	"claude-sonnet-4":   {3, 15},
	"claude-haiku-4-5":  {1, 5},
	"claude-haiku-3-5":  {0.80, 4},
}

// ModelCostUSD approximates one call's cost. Cache-read tokens are billed as
// input here (the approximation is documented); unknown models return 0.
func ModelCostUSD(model string, in, out int64) float64 {
	price, ok := modelPricePerMillion[model]
	if !ok {
		return 0
	}
	return (float64(in)*price[0] + float64(out)*price[1]) / 1e6
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

	var contents []claudeContent
	for _, raw := range rec.Message.Content {
		var c claudeContent
		if err := json.Unmarshal(raw, &c); err == nil {
			contents = append(contents, c)
		}
	}

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
				events = append(events, event.Event{
					Kind: event.KindToolCall, TS: ts, SessionID: rec.SessionID,
					ToolName: c.Name, ToolStatus: "running",
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
				ToolName: p.name, ToolStatus: status,
				DurationMs: ts.Sub(p.ts).Milliseconds(),
			})
		}
		// A user record with real text (not tool_result plumbing) is a turn
		// boundary — one user→assistant cycle of the session.
		for _, c := range contents {
			if c.Type == "text" && strings.TrimSpace(c.Text) != "" {
				events = append(events, event.Event{
					Kind: event.KindTurn, TS: ts, SessionID: rec.SessionID,
				})
				break
			}
		}
	}
	return events, rec.CWD, len(events) > 0
}
