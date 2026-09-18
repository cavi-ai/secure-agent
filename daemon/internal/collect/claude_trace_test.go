package collect

import (
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

const claudeAssistantLine = `{"type":"assistant","sessionId":"sess-1","cwd":"/repo","timestamp":"2026-09-17T12:00:00.000Z","message":{"model":"claude-sonnet-4-5","usage":{"input_tokens":100,"output_tokens":50,"cache_creation_input_tokens":900,"cache_read_input_tokens":0},"content":[{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"go test ./..."}}]}}`

func TestClaudeTraceModelCallAndToolUse(t *testing.T) {
	tr := NewClaudeTracer()
	evs, cwd, ok := tr.ParseLine(claudeAssistantLine)
	if !ok {
		t.Fatal("assistant line not parsed")
	}
	if cwd != "/repo" {
		t.Fatalf("cwd = %q", cwd)
	}
	var mc, tc *event.Event
	for i := range evs {
		switch evs[i].Kind {
		case event.KindModelCall:
			mc = &evs[i]
		case event.KindToolCall:
			tc = &evs[i]
		}
	}
	if mc == nil || mc.Model != "claude-sonnet-4-5" {
		t.Fatalf("model_call = %+v", mc)
	}
	// input + cache-creation fold into tokens_in; cache-read is not billed here.
	if mc.TokensIn != 1000 || mc.TokensOut != 50 {
		t.Fatalf("tokens = %d/%d, want 1000/50", mc.TokensIn, mc.TokensOut)
	}
	// sonnet-4-5: $3/1M in, $15/1M out → (1000*3 + 50*15)/1e6 = 0.00375
	if mc.CostUSD < 0.0037 || mc.CostUSD > 0.0038 {
		t.Fatalf("cost = %v, want ~0.00375", mc.CostUSD)
	}
	if tc == nil || tc.ToolName != "Bash" || tc.ToolStatus != "running" {
		t.Fatalf("tool_call = %+v", tc)
	}
	if mc.SessionID != "sess-1" || tc.SessionID != "sess-1" {
		t.Fatal("trace events must carry the transcript session id")
	}
	// Content never crosses into the event.
	for _, e := range evs {
		if e.Detail != "" || e.Path != "" {
			t.Fatalf("trace event carries content: %+v", e)
		}
	}
}

func TestClaudeTraceToolResultPairsDuration(t *testing.T) {
	tr := NewClaudeTracer()
	_, _, _ = tr.ParseLine(claudeAssistantLine)
	result := `{"type":"user","sessionId":"sess-1","timestamp":"2026-09-17T12:00:31.500Z","message":{"content":[{"type":"tool_result","tool_use_id":"toolu_1","is_error":false}]}}`
	evs, _, ok := tr.ParseLine(result)
	if !ok || len(evs) != 1 {
		t.Fatalf("tool_result evs = %+v", evs)
	}
	e := evs[0]
	if e.Kind != event.KindToolCall || e.ToolName != "Bash" || e.ToolStatus != "ok" {
		t.Fatalf("paired tool_call = %+v", e)
	}
	if e.DurationMs != 31500 {
		t.Fatalf("duration = %dms, want 31500", e.DurationMs)
	}
	// TS is the tool start, not the result — the waterfall needs the span.
	if e.TS.Format("15:04:05") != "12:00:00" {
		t.Fatalf("ts = %v, want the tool_use start", e.TS)
	}
}

func TestClaudeTraceToolErrorAndTurn(t *testing.T) {
	tr := NewClaudeTracer()
	_, _, _ = tr.ParseLine(claudeAssistantLine)
	errResult := `{"type":"user","sessionId":"sess-1","timestamp":"2026-09-17T12:00:05Z","message":{"content":[{"type":"tool_result","tool_use_id":"toolu_1","is_error":true}]}}`
	evs, _, _ := tr.ParseLine(errResult)
	if len(evs) != 1 || evs[0].ToolStatus != "error" {
		t.Fatalf("error tool_call = %+v", evs)
	}

	turn := `{"type":"user","sessionId":"sess-1","timestamp":"2026-09-17T12:01:00Z","message":{"content":[{"type":"text","text":"fix the bug"}]}}`
	evs, _, _ = tr.ParseLine(turn)
	if len(evs) != 1 || evs[0].Kind != event.KindTurn {
		t.Fatalf("turn = %+v", evs)
	}
}

func TestClaudeTraceRejectsNonTraceAndUnknownModelCost(t *testing.T) {
	tr := NewClaudeTracer()
	if _, _, ok := tr.ParseLine(`{"tool":"Read","pid":1}`); ok {
		t.Fatal("plugin activity line must not parse as a trace")
	}
	if _, _, ok := tr.ParseLine(`{"type":"system","sessionId":"s"}`); ok {
		t.Fatal("system records produce no trace events")
	}
	if c := ModelCostUSD("some-future-model", 1000, 1000); c != 0 {
		t.Fatalf("unknown model cost = %v, want 0 (no fabricated prices)", c)
	}
}

func TestIsClaudeTranscriptPath(t *testing.T) {
	if !IsClaudeTranscriptPath("/Users/x/.claude/projects/-repo/abc.jsonl") {
		t.Fatal("claude project transcript not recognized")
	}
	if IsClaudeTranscriptPath("/Users/x/.local/state/secure-agent/activity.jsonl") {
		t.Fatal("activity log misclassified as claude transcript")
	}
}
