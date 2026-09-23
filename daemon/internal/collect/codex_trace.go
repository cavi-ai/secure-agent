package collect

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
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
// The model comes from event_msg/thread_settings_applied when the rollout has
// one (it wins), else from the latest turn_context (one per turn; current
// codex writes no settings line). The provider comes from the settings line,
// else session_meta's model_provider. Every model_call carries the model id,
// the provider and the cost from the price tables; an id the tables do not
// know costs 0 (never a fabricated price).

type codexLine struct {
	Timestamp string          `json:"timestamp"`
	Type      string          `json:"type"` // session_meta | event_msg | response_item
	Payload   json.RawMessage `json:"payload"`
}

type codexMeta struct {
	SessionID     string `json:"session_id"`
	CWD           string `json:"cwd"`
	ModelProvider string `json:"model_provider"`
}

// codexTurnContext is the turn_context payload subset the tracer reads.
type codexTurnContext struct {
	Model string `json:"model"`
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
// thread_settings_applied or turn_context.
type CodexTracer struct {
	sessionID        string
	cwd              string
	settingsModel    string                 // model id from the latest thread_settings_applied
	settingsProvider string                 // model_provider_id from the same line
	contextModel     string                 // model id from the latest turn_context
	metaProvider     string                 // session_meta model_provider
	pending          map[string]pendingTool // call_id → open call
}

func NewCodexTracer() *CodexTracer {
	return &CodexTracer{pending: map[string]pendingTool{}}
}

// codexPrimeMaxBytes bounds the head read that restores a resumed rollout's
// session and model. The first turn_context sits past 256 KB in about a fifth
// of real rollouts (p95 1.5 MB, max 4.7 MB), so the cap is 8 MiB.
const codexPrimeMaxBytes = 8 << 20

// codexPrimeTags are the record types Prime replays; each sits in a line's
// first bytes ("timestamp" then "type", or event_msg's payload type).
var codexPrimeTags = [][]byte{[]byte(`"session_meta"`), []byte(`"turn_context"`), []byte(`"thread_settings_applied"`)}

// Prime replays the rollout head (at most codexPrimeMaxBytes of it) for
// session_meta, turn_context and thread_settings_applied, so a tracer that
// starts at a persisted offset after a daemon restart still knows the session
// and model. It emits nothing: those lines were published by the earlier run.
// Only complete lines are read; a line over 1 MiB is skipped.
func (t *CodexTracer) Prime(head io.Reader) {
	br := bufio.NewReaderSize(io.LimitReader(head, codexPrimeMaxBytes), 1024*1024)
	for {
		line, err := br.ReadSlice('\n')
		overlong := false
		for err == bufio.ErrBufferFull {
			overlong = true
			_, err = br.ReadSlice('\n')
		}
		if err != nil {
			return
		}
		if overlong {
			continue
		}
		prefix := line[:min(len(line), 256)]
		for _, tag := range codexPrimeTags {
			if bytes.Contains(prefix, tag) {
				t.ParseLine(string(line))
				break
			}
		}
	}
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

// Model returns the model id and provider: thread_settings_applied wins,
// else the latest turn_context model and session_meta's model_provider (""
// until one is consumed).
func (t *CodexTracer) Model() (id, provider string) {
	id, provider = t.settingsModel, t.settingsProvider
	if id == "" {
		id = t.contextModel
	}
	if provider == "" {
		provider = t.metaProvider
	}
	return id, provider
}

// ParseLine consumes one rollout line and returns zero or more trace events.
// ok=false means the line is not a Codex trace record; the caller still runs
// its redaction scan on it. A thread_settings_applied or turn_context line
// updates the tracer's model and returns ok=false, so it keeps that scan.
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
			t.metaProvider = meta.ModelProvider
		}
		return nil, true
	case "turn_context":
		var tc codexTurnContext
		if err := json.Unmarshal(rec.Payload, &tc); err == nil && tc.Model != "" {
			t.contextModel = tc.Model
		}
		return nil, false
	case "event_msg":
		var msg codexEventMsg
		if err := json.Unmarshal(rec.Payload, &msg); err != nil {
			return nil, false
		}
		if msg.Type == "thread_settings_applied" {
			if m := msg.ThreadSettings.Model; m != "" {
				t.settingsModel = m
				t.settingsProvider = msg.ThreadSettings.ModelProviderID
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
		model, provider := t.Model()
		return []event.Event{{
			Kind: event.KindModelCall, TS: ts, SessionID: t.sessionID,
			Model: model, Provider: provider, TokensIn: u.InputTokens, TokensOut: u.OutputTokens,
			CostUSD: ModelCostUSD(model, u.InputTokens, u.OutputTokens),
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
