package collect

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// Hook runs from Claude Code transcripts. Each command hook execution is one
// attachment record (hook_success, hook_non_blocking_error, hook_cancelled)
// with its command, duration and output. Two exceptions: a hook that blocks
// a tool call writes no attachment and appears only as the tool_result error
// "<Event>:<Tool> hook error: <stderr>"; Stop hooks are listed in full only
// by the stop_hook_summary system record, and get an attachment only when
// they print. Events keep counts and the command's script name, never
// output text.

// claudeHookInfo is one hook a stop_hook_summary lists; in-process hooks
// have the command "callback" and no duration.
type claudeHookInfo struct {
	Command    string `json:"command"`
	DurationMs int64  `json:"durationMs"`
}

// stopOutput is a Stop hook attachment held until its summary arrives.
type stopOutput struct {
	hook, status string
	chars        int64
}

// stopHoldLimit bounds held stops whose summary never arrives.
const stopHoldLimit = 64

// hookRun returns the hook execution an attachment record reports. Stop hook
// attachments are held for stopHookRuns instead, which counts each Stop hook
// once. hook_additional_context and hook_system_message records repeat text
// the hook_success record's JSON output already carries, so they are skipped.
func (t *ClaudeTracer) hookRun(rec *claudeRecord, ts time.Time) (event.Event, bool) {
	a := rec.Attachment
	if a == nil || a.HookName == "" || rec.UUID == "" {
		return event.Event{}, false
	}
	var status string
	var chars int64
	switch a.Type {
	case "hook_success":
		status, chars = hookOutcome(a)
	case "hook_non_blocking_error":
		status = "error"
	case "hook_cancelled":
		status = "cancelled"
	default:
		return event.Event{}, false
	}
	if isStopHook(a) {
		t.holdStopOutput(a.ToolUseID, hookScript(a.Command), stopOutput{hook: a.HookName, status: status, chars: chars})
		return event.Event{}, false
	}
	return hookRunEvent(hookrun.Record{
		Type: "hook_run", Version: 1, Harness: "claude",
		TS: ts, SessionID: rec.SessionID, ID: rec.UUID,
		Event: a.HookName, Script: hookScript(a.Command), Status: status,
		DurationMs: a.DurationMs, Chars: chars,
	}), true
}

func isStopHook(a *claudeAttachment) bool {
	name := a.HookEvent
	if name == "" {
		name, _, _ = strings.Cut(a.HookName, ":")
	}
	return name == "Stop" || name == "SubagentStop"
}

func (t *ClaudeTracer) holdStopOutput(stop, script string, out stopOutput) {
	if t.stops == nil || (t.stops[stop] == nil && len(t.stops) >= stopHoldLimit) {
		t.stops = map[string]map[string]stopOutput{}
	}
	if t.stops[stop] == nil {
		t.stops[stop] = map[string]stopOutput{}
	}
	t.stops[stop][script] = out
}

// stopHookRuns returns one hook run per hook a stop_hook_summary lists, with
// the output size and status of any held attachment for the same stop. A
// hookErrors entry is "[<command as run>]: <text>"; the text went back to the
// model and kept the turn going, so that hook blocked. The command there has
// its variables expanded, so hooks match by script name.
func (t *ClaudeTracer) stopHookRuns(rec *claudeRecord, ts time.Time) []event.Event {
	if rec.Subtype != "stop_hook_summary" || rec.UUID == "" {
		return nil
	}
	held := t.stops[rec.ToolUseID]
	delete(t.stops, rec.ToolUseID)
	blocked := map[string]int64{}
	for _, msg := range rec.HookErrors {
		if command, text, ok := strings.Cut(msg, "]: "); ok && strings.HasPrefix(command, "[") {
			blocked[hookScript(command[1:])] += runeCount(text)
		}
	}
	events := make([]event.Event, 0, len(rec.HookInfos))
	for i, info := range rec.HookInfos {
		script := hookScript(info.Command)
		run, ok := held[script]
		if !ok {
			run = stopOutput{hook: "Stop", status: "ok"}
		}
		if chars, ok := blocked[script]; ok {
			run.status, run.chars = "block", run.chars+chars
		}
		events = append(events, hookRunEvent(hookrun.Record{
			Type: "hook_run", Version: 1, Harness: "claude",
			TS: ts, SessionID: rec.SessionID, ID: rec.UUID + ":" + strconv.Itoa(i),
			Event: run.hook, Script: script, Status: run.status, DurationMs: info.DurationMs, Chars: run.chars,
		}))
	}
	return events
}

// hookOutcome classifies a hook_success run and counts the characters it
// returned. JSON output carries its text in the decision and context fields;
// plain output is the text itself.
func hookOutcome(a *claudeAttachment) (string, int64) {
	var out struct {
		Decision      string `json:"decision"`
		Reason        string `json:"reason"`
		SystemMessage string `json:"systemMessage"`
		Specific      struct {
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
			AdditionalContext        string `json:"additionalContext"`
		} `json:"hookSpecificOutput"`
	}
	stdout := strings.TrimSpace(a.Stdout)
	if strings.HasPrefix(stdout, "{") && json.Unmarshal([]byte(stdout), &out) == nil {
		chars := runeCount(out.Reason, out.SystemMessage, out.Specific.PermissionDecisionReason, out.Specific.AdditionalContext)
		switch {
		case out.Specific.PermissionDecision == "deny":
			return "deny", chars
		case out.Decision == "block":
			return "block", chars
		case chars > 0:
			return "inject", chars
		}
		return "ok", 0
	}
	var text string
	_ = json.Unmarshal(a.Content, &text)
	if n := runeCount(text); n > 0 {
		return "inject", n
	}
	return "ok", 0
}

// hookBlockError matches the tool_result Claude Code writes when a hook
// blocks the call.
var hookBlockError = regexp.MustCompile(`^(?:<tool_use_error>)?([A-Za-z]+(?::\S+)?) hook error: `)

// blockedByHook returns the hook run behind a tool_result a hook blocked. The
// harness does not record which command blocked, so Detail stays empty.
func blockedByHook(c claudeContent, sessionID string, ts time.Time) (event.Event, bool) {
	if !c.IsError || c.ToolUseID == "" {
		return event.Event{}, false
	}
	text := toolResultText(c.Content)
	m := hookBlockError.FindStringSubmatchIndex(text)
	if m == nil {
		return event.Event{}, false
	}
	return hookRunEvent(hookrun.Record{
		Type: "hook_run", Version: 1, Harness: "claude",
		TS: ts, SessionID: sessionID, ID: "block:" + c.ToolUseID,
		Event: text[m[2]:m[3]], Status: "block", Chars: runeCount(text[m[1]:]),
	}), true
}

// toolResultText returns a tool_result body's text: the string itself, or
// the first text block.
func toolResultText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var blocks []claudeContent
	if json.Unmarshal(raw, &blocks) == nil {
		for _, b := range blocks {
			if b.Type == "text" {
				return b.Text
			}
		}
	}
	return ""
}

// hookScriptName finds a script file name inside a hook command, including
// one passed as a quoted argument ("runpy.run_path('/x/guard.py')").
var hookScriptName = regexp.MustCompile(`[A-Za-z0-9_.-]+\.(?:py|sh|bash|zsh|mjs|cjs|js|ts|cmd|rb|pl)\b`)

// hookScript names a hook by its command's script ("python3 /x/secret_guard.py"
// -> "secret_guard.py"), else its first word. Paths and arguments are never
// kept: commands carry home directories.
func hookScript(command string) string {
	if name := hookScriptName.FindString(command); name != "" {
		return name
	}
	if words := strings.Fields(command); len(words) > 0 {
		first := strings.Trim(words[0], `"'`)
		return first[strings.LastIndex(first, "/")+1:]
	}
	return ""
}

func runeCount(parts ...string) int64 {
	var n int
	for _, p := range parts {
		n += utf8.RuneCountInString(p)
	}
	return int64(n)
}
