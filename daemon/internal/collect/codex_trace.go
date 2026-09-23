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
// event_msg/thread_settings_applied names the model and provider; every later
// model_call carries that model id and its cost from the price tables. An id
// the tables do not know costs 0 (never a fabricated price), and a rollout
// without the settings line yields model_calls with no model and cost 0.

type codexLine struct {
	Timestamp string          `json:"timestamp"`
	Type      string          `json:"type"` // session_meta | event_msg | response_item
	Payload   json.RawMessage `json:"payload"`
}

type codexMeta struct {
	SessionID string `json:"session_id"`
	CWD       string `json:"cwd"`
}

// codexEventMsg is the event_msg payload subset the tracer reads.
type codexEventMsg struct {
	Type string `json:"type"` // token_count | thread_settings_applied | ...
	Info struct {
		LastTokenUsage struct {
			InputTokens  int64 `json:"input_tokens"`
			CachedInput  int64 `json:"cached_input_tokens"`
			OutputTokens int64 `json:"output_tokens"`
		} `json:"last_token_usage"`
	} `json:"info"`
	ThreadSettings struct {
		Model           string `json:"model"`
		ModelProviderID string `json:"model_provider_id"`
	} `json:"thread_settings"`
}

type codexResponseItem struct {
	Type   string `json:"type"` // function_call | function_call_output | ...
	ID     string `json:"id"`
	CallID string `json:"call_id"`
	Name   string `json:"name"`
}

// CodexTracer turns rollout lines into trace events; stateful per file for
// call_id pairing, the session id from session_meta and the model from
// thread_settings_applied.
type CodexTracer struct {
	sessionID string
	cwd       string
	model     string                 // model id as written by thread_settings_applied
	provider  string                 // model_provider_id from the same line
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

// Model returns the model id and provider learned from the latest
// thread_settings_applied line ("" until one is consumed).
func (t *CodexTracer) Model() (id, provider string) { return t.model, t.provider }

// ParseLine consumes one rollout line and returns zero or more trace events.
// ok=false means the line is not a Codex trace record; the caller still runs
// its redaction scan on it. A thread_settings_applied line updates the
// tracer's model and returns ok=false, so it keeps that scan.
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
		var msg codexEventMsg
		if err := json.Unmarshal(rec.Payload, &msg); err != nil {
			return nil, false
		}
		if msg.Type == "thread_settings_applied" {
			if m := msg.ThreadSettings.Model; m != "" {
				t.model = m
				t.provider = msg.ThreadSettings.ModelProviderID
			}
			return nil, false
		}
		if msg.Type != "token_count" || t.sessionID == "" {
			return nil, false
		}
		u := msg.Info.LastTokenUsage
		if u.InputTokens == 0 && u.OutputTokens == 0 {
			return nil, true
		}
		return []event.Event{{
			Kind: event.KindModelCall, TS: ts, SessionID: t.sessionID,
			Model: t.model, TokensIn: u.InputTokens, TokensOut: u.OutputTokens,
			CostUSD: ModelCostUSD(t.model, u.InputTokens, u.OutputTokens),
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
