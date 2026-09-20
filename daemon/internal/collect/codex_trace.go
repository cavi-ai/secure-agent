package collect

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// Codex rollout trace parsing (~/.codex/sessions/**/rollout-*.jsonl).
// Line 1 is session_meta (session id + cwd); event_msg/token_count carries
// per-call token deltas; response_item function_call / function_call_output
// pair by call_id for durations. Content (arguments, output) is NEVER
// carried into events — names, durations and token counts only.
// Codex rollout lines omit the model id, so model_call events carry tokens
// without a model and cost 0 — never a fabricated price.

type codexLine struct {
	Timestamp string          `json:"timestamp"`
	Type      string          `json:"type"` // session_meta | event_msg | response_item
	Payload   json.RawMessage `json:"payload"`
}

type codexMeta struct {
	SessionID string `json:"session_id"`
	CWD       string `json:"cwd"`
}

type codexTokenCount struct {
	Type string `json:"type"` // token_count
	Info struct {
		LastTokenUsage struct {
			InputTokens  int64 `json:"input_tokens"`
			CachedInput  int64 `json:"cached_input_tokens"`
			OutputTokens int64 `json:"output_tokens"`
		} `json:"last_token_usage"`
	} `json:"info"`
}

type codexResponseItem struct {
	Type   string `json:"type"` // function_call | function_call_output | ...
	ID     string `json:"id"`
	CallID string `json:"call_id"`
	Name   string `json:"name"`
}

// CodexTracer turns rollout lines into trace events; stateful per file for
// call_id pairing and the session id from session_meta.
type CodexTracer struct {
	sessionID string
	cwd       string
	pending   map[string]pendingTool // call_id → open call
}

func NewCodexTracer() *CodexTracer {
	return &CodexTracer{pending: map[string]pendingTool{}}
}

// IsCodexRolloutPath reports whether a tailed file is a Codex rollout log —
// under the default ~/.codex/sessions or a custom CODEX_HOME.
func IsCodexRolloutPath(path string) bool {
	return strings.Contains(path, "/sessions/") &&
		strings.Contains(filepath.Base(path), "rollout-") &&
		strings.HasSuffix(path, ".jsonl")
}

// Session returns the session identity learned from session_meta ("" until
// the first line is consumed).
func (t *CodexTracer) Session() (id, cwd string) { return t.sessionID, t.cwd }

// ParseLine consumes one rollout line and returns zero or more trace events.
// ok=false means the line is not a Codex rollout record.
func (t *CodexTracer) ParseLine(line string) (events []event.Event, ok bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "{") || !strings.Contains(trimmed, `"payload"`) {
		return nil, false
	}
	var rec codexLine
	if err := json.Unmarshal([]byte(trimmed), &rec); err != nil {
		return nil, false
	}
	ts := time.Now()
	if rec.Timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, rec.Timestamp); err == nil {
			ts = parsed
		}
	}

	switch rec.Type {
	case "session_meta":
		var meta codexMeta
		if err := json.Unmarshal(rec.Payload, &meta); err == nil {
			t.sessionID = meta.SessionID
			t.cwd = meta.CWD
		}
		return nil, true
	case "event_msg":
		var tc codexTokenCount
		if err := json.Unmarshal(rec.Payload, &tc); err != nil || tc.Type != "token_count" || t.sessionID == "" {
			return nil, false
		}
		u := tc.Info.LastTokenUsage
		if u.InputTokens == 0 && u.OutputTokens == 0 {
			return nil, true
		}
		return []event.Event{{
			Kind: event.KindModelCall, TS: ts, SessionID: t.sessionID,
			TokensIn: u.InputTokens, TokensOut: u.OutputTokens, // model unknown: cost 0
		}}, true
	case "response_item":
		var item codexResponseItem
		if err := json.Unmarshal(rec.Payload, &item); err != nil || t.sessionID == "" {
			return nil, false
		}
		switch item.Type {
		case "function_call":
			if item.CallID == "" || item.Name == "" {
				return nil, true
			}
			t.pending[item.CallID] = pendingTool{name: item.Name, ts: ts}
			return []event.Event{{
				Kind: event.KindToolCall, TS: ts, SessionID: t.sessionID,
				CallID: item.CallID, ToolName: item.Name, ToolStatus: "running",
			}}, true
		case "function_call_output":
			p, found := t.pending[item.CallID]
			if !found {
				return nil, true
			}
			delete(t.pending, item.CallID)
			return []event.Event{{
				Kind: event.KindToolCall, TS: p.ts, SessionID: t.sessionID,
				CallID: item.CallID, ToolName: p.name, ToolStatus: "ok",
				DurationMs: ts.Sub(p.ts).Milliseconds(),
			}}, true
		}
		return nil, true
	}
	return nil, false
}
