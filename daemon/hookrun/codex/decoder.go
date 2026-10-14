// Package codex adapts Codex app-server notifications to the shared hook contract.
package codex

import (
	"encoding/json"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
)

// Decoder accepts host envelopes containing app-server v2 notifications.
type Decoder struct{}

var _ hookrun.Decoder = Decoder{}

func (Decoder) Decode(line []byte) (hookrun.Record, bool, error) {
	var envelope struct {
		ID           json.RawMessage   `json:"id"`
		Notification json.RawMessage   `json:"notification"`
		Script       string            `json:"script"`
		Evidence     *hookrun.Evidence `json:"evidence"`
	}
	if json.Unmarshal(line, &envelope) != nil {
		return hookrun.Record{}, false, errors.New("invalid notification JSON")
	}
	raw := envelope.Notification
	if len(raw) == 0 {
		raw = line
	}
	var notification struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if json.Unmarshal(raw, &notification) != nil {
		return hookrun.Record{}, false, errors.New("invalid notification envelope")
	}
	if notification.Method != "hook/completed" {
		return hookrun.Record{}, false, nil
	}
	var id string
	if json.Unmarshal(envelope.ID, &id) != nil {
		return hookrun.Record{}, true, errors.New("hook completion requires a stable host delivery id")
	}
	executionID, err := hookrun.ExecutionID("codex", id)
	if err != nil {
		return hookrun.Record{}, true, err
	}
	var params struct {
		ThreadID string `json:"threadId"`
		Run      struct {
			EventName   string `json:"eventName"`
			Status      string `json:"status"`
			CompletedAt *int64 `json:"completedAt"`
			DurationMs  *int64 `json:"durationMs"`
			Entries     []struct {
				Kind string `json:"kind"`
				Text string `json:"text"`
			} `json:"entries"`
		} `json:"run"`
	}
	if json.Unmarshal(notification.Params, &params) != nil {
		return hookrun.Record{}, true, errors.New("invalid hook completion")
	}
	eventName, found := codexHookEvents[params.Run.EventName]
	if !found || params.Run.CompletedAt == nil || *params.Run.CompletedAt <= 0 {
		return hookrun.Record{}, true, errors.New("hook completion requires a supported event and completion time")
	}
	evidence := envelope.Evidence
	if evidence == nil {
		evidence = &hookrun.Evidence{}
	}
	evidence.DurationKnown = params.Run.DurationMs != nil
	evidence.CharsKnown = params.Run.Entries != nil
	contextChars := int64(0)
	evidence.ContextChars = nil
	if evidence.CharsKnown {
		evidence.ContextChars = &contextChars
	}
	r := hookrun.Record{Type: "hook_run", Version: 2, Harness: "codex", SessionID: params.ThreadID,
		ID: executionID, TS: time.Unix(*params.Run.CompletedAt, 0).UTC(), Event: eventName, Script: envelope.Script}
	r.Evidence = evidence
	if params.Run.DurationMs != nil {
		r.DurationMs = *params.Run.DurationMs
	}
	for _, entry := range params.Run.Entries {
		if entry.Kind == "context" {
			contextChars += int64(utf8.RuneCountInString(entry.Text))
		}
		// Only model-facing context and decision feedback count as returned
		// characters. UI warnings, diagnostics and status messages do not.
		switch entry.Kind {
		case "context", "feedback", "stop":
			r.Chars += int64(utf8.RuneCountInString(entry.Text))
		}
	}
	switch params.Run.Status {
	case "completed":
		r.Status = "ok"
		if r.Chars > 0 {
			r.Status = "inject"
		}
	case "failed":
		r.Status = "error"
	case "blocked", "stopped":
		r.Status = "block"
	default:
		return hookrun.Record{}, true, errors.New("unsupported hook completion status")
	}
	if err := r.Validate(); err != nil {
		return hookrun.Record{}, true, err
	}
	return r, true, nil
}

var codexHookEvents = map[string]string{
	"preToolUse": "PreToolUse", "permissionRequest": "PermissionRequest", "postToolUse": "PostToolUse",
	"preCompact": "PreCompact", "postCompact": "PostCompact", "sessionStart": "SessionStart", "sessionEnd": "SessionEnd",
	"userPromptSubmit": "UserPromptSubmit", "subagentStart": "SubagentStart", "subagentStop": "SubagentStop",
	"stop": "Stop", "interrupt": "Interrupt",
}
