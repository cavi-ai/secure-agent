package collect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestForwardedHookRunAttribution(t *testing.T) {
	for _, harness := range []string{"claude", "codex", "openclaw", "hermes", "opencode"} {
		t.Run(harness, func(t *testing.T) {
			r := hookrun.Record{Type: "hook_run", Version: 1, Harness: harness, SessionID: "session-1", ID: harness + ":delivery-1",
				TS: time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC), Event: "before_tool", Status: "block", DurationMs: 12, Chars: 4}
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
			if seen.Harness != harness || seen.ID != r.SessionID || !seen.At.Equal(r.TS) {
				t.Fatalf("session = %+v", seen)
			}
			if ts.SessionForPath("/logs/activity.jsonl") != "" {
				t.Fatal("shared activity log associated with a single session")
			}
		})
	}
}

func TestHookIngestionCountsAcceptedDeliveryAndRejectedRecordOnce(t *testing.T) {
	b := bus.New(1)
	defer b.Close()
	sub := b.Subscribe()
	b.Publish(event.Event{Kind: event.KindTurn}) // backpressure the hook delivery
	r := hookrun.Record{Type: "hook_run", Version: 1, Harness: "codex", SessionID: "s", ID: "codex:r", TS: time.Now(), Event: "PreToolUse", Status: "ok"}
	data, _ := json.Marshal(r)
	p := filepath.Join(t.TempDir(), "activity.jsonl")
	invalid := `{"type":"hook_run","harness":"private-untrusted-value","version":999}`
	if err := os.WriteFile(p, append([]byte(invalid+"\n"), append(data, '\n')...), 0600); err != nil {
		t.Fatal(err)
	}
	var accepted, rejected int
	ts := NewTranscriptScanner(b, []string{p})
	ts.OnHookAccepted = func(h string) {
		if h != "codex" {
			t.Errorf("untrusted harness %q", h)
		}
		accepted++
	}
	ts.OnHookRejected = func() { rejected++ }
	offsets := map[string]int64{}
	ts.tailFile(p, offsets, nil)
	if accepted != 0 || rejected != 1 {
		t.Fatalf("before delivery: accepted=%d rejected=%d", accepted, rejected)
	}
	<-sub
	ts.tailFile(p, offsets, nil)
	ts.tailFile(p, offsets, nil)
	if accepted != 1 || rejected != 1 {
		t.Fatalf("after retry: accepted=%d rejected=%d", accepted, rejected)
	}
	if got := <-sub; got.Kind != event.KindHookRun {
		t.Fatalf("event = %+v", got)
	}
}

func TestForwardedHookRunRejectsInvalidContract(t *testing.T) {
	line := `{"type":"hook_run","version":2,"harness":"codex","session_id":"thread-1","run_id":"delivery-1","ts":"2026-10-13T10:00:00Z","event":"PreToolUse","status":"ok","tool":"Bash"}`
	ts := &TranscriptScanner{OnSessionSeen: func(TraceSession) { t.Fatal("invalid record attributed") }}
	if events := ts.eventsForLine("/logs/activity.jsonl", line, 0, 0, nil); len(events) != 0 {
		t.Fatalf("invalid hook became an event: %+v", events)
	}
}
