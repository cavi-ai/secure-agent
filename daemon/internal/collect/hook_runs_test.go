package collect

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestForwardedHookRunAttribution(t *testing.T) {
	r := hookrun.Record{Type: "hook_run", Version: 1, Harness: "codex", SessionID: "thread-1", ID: "codex:delivery-1",
		TS: time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC), Event: "PreToolUse", Status: "block", DurationMs: 12, Chars: 4}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var seen TraceSession
	ts := &TranscriptScanner{OnSessionSeen: func(s TraceSession) { seen = s }}
	events := ts.eventsForLine("/logs/activity.jsonl", string(data), 0, 0, nil)
	if len(events) != 1 || events[0].Kind != event.KindHookRun || events[0].SessionID != r.SessionID || events[0].CallID != r.ID || events[0].ToolName != r.Event || events[0].ToolStatus != r.Status || events[0].DurationMs != 12 || events[0].Chars != 4 {
		t.Fatalf("events = %+v", events)
	}
	if seen.Harness != "codex" || seen.ID != r.SessionID || !seen.At.Equal(r.TS) {
		t.Fatalf("session = %+v", seen)
	}
	if ts.SessionForPath("/logs/activity.jsonl") != "" {
		t.Fatal("shared activity log associated with a single session")
	}
}

func TestForwardedHookRunRejectsInvalidContract(t *testing.T) {
	line := `{"type":"hook_run","version":2,"harness":"codex","session_id":"thread-1","run_id":"delivery-1","ts":"2026-10-13T10:00:00Z","event":"PreToolUse","status":"ok","tool":"Bash"}`
	ts := &TranscriptScanner{OnSessionSeen: func(TraceSession) { t.Fatal("invalid record attributed") }}
	if events := ts.eventsForLine("/logs/activity.jsonl", line, 0, 0, nil); len(events) != 0 {
		t.Fatalf("invalid hook became an event: %+v", events)
	}
}
