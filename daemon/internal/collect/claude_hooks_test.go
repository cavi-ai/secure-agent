package collect

import (
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestClaudeTraceHookRuns(t *testing.T) {
	const at = `"sessionId":"sess-1","timestamp":"2026-09-23T10:00:00.000Z"`
	cases := []struct {
		name, line                   string
		hook, script, status, callID string
		chars, durationMs            int64
	}{
		{
			name: "plain output is returned text",
			line: `{"type":"attachment",` + at + `,"uuid":"u1","attachment":{"type":"hook_success","hookName":"UserPromptSubmit","command":"bash \"${CLAUDE_PLUGIN_ROOT}/scripts/user-prompt-hook.sh\"","exitCode":0,"durationMs":16,"content":"[18:29 EDT]","stdout":"[18:29 EDT]\n"}}`,
			hook: "UserPromptSubmit", script: "user-prompt-hook.sh", status: "inject", callID: "u1", chars: 11, durationMs: 16,
		},
		{
			name: "json additional context is returned text",
			line: `{"type":"attachment",` + at + `,"uuid":"u2","attachment":{"type":"hook_success","hookName":"SessionStart:startup","command":"\"${CLAUDE_PLUGIN_ROOT}/hooks/run-hook.cmd\" session-start","exitCode":0,"durationMs":39,"content":"","stdout":"{\"hookSpecificOutput\":{\"hookEventName\":\"SessionStart\",\"additionalContext\":\"héllo\"}}"}}`,
			hook: "SessionStart:startup", script: "run-hook.cmd", status: "inject", callID: "u2", chars: 5, durationMs: 39,
		},
		{
			name: "allow with no text",
			line: `{"type":"attachment",` + at + `,"uuid":"u3","attachment":{"type":"hook_success","hookName":"PreToolUse:Bash","command":"python3 /home/user/.claude/hooks/secret_guard.py","exitCode":0,"durationMs":29,"content":"","stdout":"{\"permission\": \"allow\"}"}}`,
			hook: "PreToolUse:Bash", script: "secret_guard.py", status: "ok", callID: "u3", durationMs: 29,
		},
		{
			name: "json deny",
			line: `{"type":"attachment",` + at + `,"uuid":"u4","attachment":{"type":"hook_success","hookName":"PreToolUse:Edit","command":"python3 guard.py","exitCode":0,"durationMs":5,"content":"","stdout":"{\"hookSpecificOutput\":{\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"no\"}}"}}`,
			hook: "PreToolUse:Edit", script: "guard.py", status: "deny", callID: "u4", chars: 2, durationMs: 5,
		},
		{
			name: "non-blocking error",
			line: `{"type":"attachment",` + at + `,"uuid":"u5","attachment":{"type":"hook_non_blocking_error","hookName":"PreToolUse:Read","command":"python3 -c \"import runpy; runpy.run_path('/home/user/hooks/guard.py',run_name='__main__')\"","exitCode":1,"durationMs":40,"stderr":"FileNotFoundError: guard-rules.json"}}`,
			hook: "PreToolUse:Read", script: "guard.py", status: "error", callID: "u5", durationMs: 40,
		},
		{
			name: "cancelled",
			line: `{"type":"attachment",` + at + `,"uuid":"u6","attachment":{"type":"hook_cancelled","hookName":"PostToolUse:Bash","command":"node post-gate.mjs"}}`,
			hook: "PostToolUse:Bash", script: "post-gate.mjs", status: "cancelled", callID: "u6",
		},
		{
			name: "blocking hook seen only in the tool result",
			line: `{"type":"user",` + at + `,"uuid":"u7","message":{"content":[{"type":"tool_result","tool_use_id":"toolu_9","is_error":true,"content":"PreToolUse:Bash hook error: DENIED: x"}]}}`,
			hook: "PreToolUse:Bash", status: "block", callID: "block:toolu_9", chars: 9,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evs, _, ok := NewClaudeTracer().ParseLine(tc.line)
			if !ok {
				t.Fatal("line not parsed")
			}
			var runs []event.Event
			for _, e := range evs {
				if e.Kind == event.KindHookRun {
					runs = append(runs, e)
				}
			}
			if len(runs) != 1 {
				t.Fatalf("hook runs = %+v, want one", evs)
			}
			got := runs[0]
			if got.ToolName != tc.hook || got.Detail != tc.script || got.ToolStatus != tc.status ||
				got.CallID != tc.callID || got.Chars != tc.chars || got.DurationMs != tc.durationMs || got.SessionID != "sess-1" {
				t.Fatalf("hook run = %+v, want hook=%s script=%s status=%s call=%s chars=%d ms=%d",
					got, tc.hook, tc.script, tc.status, tc.callID, tc.chars, tc.durationMs)
			}
		})
	}
}

func TestClaudeTraceSkipsNonHookRecords(t *testing.T) {
	const at = `"sessionId":"sess-1","timestamp":"2026-09-23T10:00:00.000Z"`
	for _, line := range []string{
		// Context records repeat what the hook_success output already counted.
		`{"type":"attachment",` + at + `,"uuid":"c1","attachment":{"type":"hook_additional_context","hookName":"SessionStart","content":["text"]}}`,
		`{"type":"attachment",` + at + `,"uuid":"c2","attachment":{"type":"hook_system_message","hookName":"PreToolUse:Edit","content":"text"}}`,
		`{"type":"attachment",` + at + `,"uuid":"c3","attachment":{"type":"output_style","style":{}}}`,
		// An ordinary tool error is not a hook block.
		`{"type":"user",` + at + `,"uuid":"c4","message":{"content":[{"type":"tool_result","tool_use_id":"toolu_8","is_error":true,"content":"<tool_use_error>File has not been read yet.</tool_use_error>"}]}}`,
	} {
		evs, _, _ := NewClaudeTracer().ParseLine(line)
		for _, e := range evs {
			if e.Kind == event.KindHookRun {
				t.Fatalf("%s: unexpected hook run %+v", line, e)
			}
		}
	}
}

// Stop hooks are listed in full only by stop_hook_summary; the attachment a
// printing Stop hook writes adds its output to that one run, never a second.
func TestClaudeTraceStopHookSummary(t *testing.T) {
	const at = `"sessionId":"sess-1","timestamp":"2026-10-13T10:00:00.000Z"`
	tr := NewClaudeTracer()
	attachment := `{"type":"attachment",` + at + `,"uuid":"s0","attachment":{"type":"hook_success","hookName":"Stop","toolUseID":"stop-1","hookEvent":"Stop","content":"banner","stdout":"banner\n","stderr":"","exitCode":0,"command":"python3 \"$CLAUDE_PROJECT_DIR/.claude/hooks/discipline.py\"","durationMs":70}}`
	if evs, _, _ := tr.ParseLine(attachment); len(evs) != 0 {
		t.Fatalf("Stop attachment emitted %+v, want it held for the summary", evs)
	}
	summary := `{"type":"system","subtype":"stop_hook_summary",` + at + `,"uuid":"s1","toolUseID":"stop-1","isSidechain":false,"hookCount":4,` +
		`"hookInfos":[{"command":"python3 \"$CLAUDE_PROJECT_DIR/.claude/hooks/discipline.py\"","durationMs":70},{"command":"node \"${CLAUDE_PLUGIN_ROOT}/scripts/stop-gate.mjs\"","durationMs":348},{"command":"python3 \"${CLAUDE_PLUGIN_ROOT}/hooks/policy.py\" Stop"},{"command":"callback"}],` +
		`"hookErrors":["[python3 \"/home/user/plugins/policy.py\" Stop]: BLOCKED -- no"],"hookAdditionalContext":[],"preventedContinuation":false,"stopReason":"","hasOutput":true,"level":"suggestion"}`
	evs, _, ok := tr.ParseLine(summary)
	if !ok {
		t.Fatal("summary not parsed")
	}
	type run struct {
		call, hook, script, status string
		chars, ms                  int64
	}
	var got []run
	for _, e := range evs {
		if e.Kind != event.KindHookRun || e.SessionID != "sess-1" {
			t.Fatalf("unexpected event %+v", e)
		}
		got = append(got, run{e.CallID, e.ToolName, e.Detail, e.ToolStatus, e.Chars, e.DurationMs})
	}
	want := []run{
		{"s1:0", "Stop", "discipline.py", "inject", 6, 70},
		{"s1:1", "Stop", "stop-gate.mjs", "ok", 0, 348},
		{"s1:2", "Stop", "policy.py", "block", 13, 0},
		{"s1:3", "Stop", "callback", "ok", 0, 0},
	}
	if len(got) != len(want) {
		t.Fatalf("runs = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("run %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if len(tr.stops) != 0 {
		t.Fatalf("held stops = %v, want the summary to release them", tr.stops)
	}
}
