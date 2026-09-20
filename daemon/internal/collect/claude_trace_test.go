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

// Every tool_use and its tool_result carry the harness's own id, so the store
// can key one row per call (start upserts, completion updates it). Without
// CallID a start row stayed "running" forever beside a duplicate completion.
func TestClaudeTraceToolCallsCarryCallID(t *testing.T) {
	tr := NewClaudeTracer()
	evs, _, _ := tr.ParseLine(claudeAssistantLine)
	var start *event.Event
	for i := range evs {
		if evs[i].Kind == event.KindToolCall {
			start = &evs[i]
		}
	}
	if start == nil || start.CallID != "toolu_1" {
		t.Fatalf("start call id = %+v, want toolu_1", start)
	}
	result := `{"type":"user","sessionId":"sess-1","timestamp":"2026-09-17T12:00:31.500Z","message":{"content":[{"type":"tool_result","tool_use_id":"toolu_1","is_error":false}]}}`
	evs, _, _ = tr.ParseLine(result)
	if len(evs) != 1 || evs[0].CallID != "toolu_1" || evs[0].ToolStatus != "ok" {
		t.Fatalf("completion = %+v, want toolu_1/ok", evs)
	}
}

// Claude writes user prompts as content BLOCKS or as a bare JSON string. The
// string form was missed, which is why turns were near zero in the live DB.
func TestClaudeTraceTurnDetectsStringContent(t *testing.T) {
	tr := NewClaudeTracer()
	stringPrompt := `{"type":"user","sessionId":"s1","timestamp":"2026-09-17T12:00:00Z","message":{"content":"take the handoff packet"}}`
	evs, _, ok := tr.ParseLine(stringPrompt)
	if !ok || len(evs) != 1 || evs[0].Kind != event.KindTurn {
		t.Fatalf("string prompt evs = %+v, want one turn", evs)
	}
	// Tool-result plumbing and system wrappers are NOT turns.
	for _, line := range []string{
		`{"type":"user","sessionId":"s1","message":{"content":[{"type":"tool_result","tool_use_id":"x"}]}}`,
		`{"type":"user","sessionId":"s1","message":{"content":"<task-notification>\n<task-id>abc</task-id>"}}`,
	} {
		if evs, _, _ := tr.ParseLine(line); len(evs) != 0 {
			t.Fatalf("non-prompt produced %+v, want no turn", evs)
		}
	}
}

// Price lookup resolves current families and dated/suffixed ids by prefix.
func TestModelCostPrefixMatch(t *testing.T) {
	// A dated id must resolve to its family price, not cost 0.
	if c := ModelCostUSD("claude-sonnet-4-5-20250929", 1_000_000, 0); c <= 0 {
		t.Fatalf("dated sonnet id cost = %v, want > 0", c)
	}
	// The live fleet's ids: fable/opus-5/sonnet-5 must all price.
	for _, m := range []string{"claude-fable-5-1", "claude-opus-5", "claude-sonnet-5"} {
		if c := ModelCostUSD(m, 1_000_000, 0); c <= 0 {
			t.Errorf("%s cost = 0, must be priced", m)
		}
	}
	// Unknown models stay honestly 0.
	if c := ModelCostUSD("gpt-9-ultra", 1_000_000, 0); c != 0 {
		t.Errorf("unknown model cost = %v, want 0", c)
	}
}

// isMeta records (injected context) and isSidechain records (subagent
// conversations) must never read as operator turns — the noise that kept
// turn counts at ~5% of real prompts.
func TestClaudeTraceMetaAndSidechainNotTurns(t *testing.T) {
	tr := NewClaudeTracer()
	meta := `{"type":"user","sessionId":"s1","isMeta":true,"message":{"content":"cached context dump"}}`
	side := `{"type":"user","sessionId":"s1","isSidechain":true,"message":{"content":"subagent exploring"}}`
	for _, line := range []string{meta, side} {
		evs, _, _ := tr.ParseLine(line)
		for _, e := range evs {
			if e.Kind == event.KindTurn {
				t.Fatalf("injected record produced a turn: %+v", evs)
			}
		}
	}
	// A genuine prompt still counts.
	evs, _, _ := tr.ParseLine(`{"type":"user","sessionId":"s1","message":{"content":"fix the bug"}}`)
	if len(evs) != 1 || evs[0].Kind != event.KindTurn {
		t.Fatalf("real prompt evs = %+v, want one turn", evs)
	}
}
