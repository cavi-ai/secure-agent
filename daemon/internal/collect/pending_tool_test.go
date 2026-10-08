package collect

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestClaudeRetiresUnfinishedCallsButCompletesRecentCalls(t *testing.T) {
	tracer := NewClaudeTracer()
	retired := 0
	for i := 0; i < 10000; i++ {
		line := fmt.Sprintf(`{"type":"assistant","sessionId":"s","timestamp":"2026-10-08T12:00:00Z","message":{"content":[{"type":"tool_use","id":"call-%d","name":"Read"}]}}`, i)
		events, _, _ := tracer.ParseLine(line)
		for _, e := range events {
			if e.ToolStatus == "incomplete" {
				retired++
			}
		}
	}
	if retired == 0 {
		t.Fatal("unfinished calls never retired")
	}
	events, _, _ := tracer.ParseLine(`{"type":"user","sessionId":"s","timestamp":"2026-10-08T12:00:01Z","message":{"content":[{"type":"tool_result","tool_use_id":"call-9999"}]}}`)
	if len(events) != 1 || events[0].ToolStatus != "ok" || events[0].DurationMs != 1000 {
		t.Fatalf("recent completion lost: %+v", events)
	}
}

func TestTranscriptPublishesRetirementOnMetadataLine(t *testing.T) {
	ts := NewTranscriptScanner(nil, nil)
	p := "/fixture/.codex/sessions/rollout-test.jsonl"
	source := strings.NewReader("")
	ts.eventsForLine(p, `{"type":"session_meta","timestamp":"2026-10-08T12:00:00Z","payload":{"session_id":"s"}}`, 0, 0, source)
	ts.eventsForLine(p, `{"type":"response_item","timestamp":"2026-10-08T12:00:00Z","payload":{"type":"function_call","call_id":"a","name":"read"}}`, 0, 0, source)
	events := ts.eventsForLine(p, `{"type":"turn_context","timestamp":"2026-10-10T12:00:00Z","payload":{"model":"local"}}`, 0, 0, source)
	if len(events) != 1 || events[0].ToolStatus != "incomplete" {
		t.Fatalf("metadata line lost retirement: %+v", events)
	}
}

func TestCodexRetiresAgedCallsBeforeResults(t *testing.T) {
	tc := NewCodexTracer("")
	tc.ParseLine(`{"type":"session_meta","timestamp":"2026-10-08T12:00:00Z","payload":{"session_id":"s"}}`)
	tc.ParseLine(`{"type":"response_item","timestamp":"2026-10-08T12:00:00Z","payload":{"type":"function_call","call_id":"a","name":"read"}}`)
	events, _ := tc.ParseLine(`{"type":"response_item","timestamp":"2026-10-10T12:00:00Z","payload":{"type":"function_call_output","call_id":"a"}}`)
	if len(events) != 2 || events[0].ToolStatus != "incomplete" || events[1].ToolStatus != "ok" || events[1].DurationMs != 0 {
		t.Fatalf("aged pairing or late result lost: %+v", events)
	}
}

func TestPendingToolsBoundAndLateCompletion(t *testing.T) {
	var p pendingTools
	base := time.Now()
	for i := 0; i < pendingToolLimit+100; i++ {
		p.add(fmt.Sprint(i), "s", pendingTool{name: "read", ts: base})
	}
	if len(p.byID) != pendingToolLimit || p.order.Len() != pendingToolLimit {
		t.Fatal("pending state exceeded cap")
	}
	if _, ok := p.byID["0"]; ok {
		t.Fatal("oldest pairing retained past cap")
	}
	if _, ok := p.completion(fmt.Sprint(pendingToolLimit+99), "s", "ok", base.Add(time.Second)); !ok {
		t.Fatal("recent pairing lost")
	}
}
