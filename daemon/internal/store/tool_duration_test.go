package store

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestEvictedToolCompletionUpdatesOriginalRow(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	start := event.Event{Kind: event.KindToolCall, TS: now, SessionID: "s", CallID: "c", ToolName: "Read", ToolStatus: "running"}
	s.PutEvent(start)
	done := event.Event{Kind: event.KindToolCall, TS: now.Add(time.Second), SessionID: "s", CallID: "c", ToolStatus: "ok", Detail: "tool duration unavailable: start not retained"}
	s.PutEvent(done)
	s.PutEvent(start)
	rows := s.RecentEvents(10)
	if len(rows) != 1 || rows[0].ToolName != "Read" || rows[0].ToolStatus != "ok" || rows[0].Detail != done.Detail || rows[0].DurationMs != 0 || !rows[0].TS.Equal(now) {
		t.Fatalf("late completion: %+v", rows)
	}
	done.DurationMs = 1000
	done.Detail = ""
	s.PutEvent(done)
	rows = s.RecentEvents(10)
	if rows[0].DurationMs != 1000 || rows[0].Detail != "" {
		t.Fatalf("recovered timing: %+v", rows[0])
	}
	done.DurationMs = 0
	done.Detail = "tool duration unavailable: start not retained"
	s.PutEvent(done)
	rows = s.RecentEvents(10)
	if rows[0].DurationMs != 1000 || rows[0].Detail != "" {
		t.Fatalf("replayed incomplete timing: %+v", rows[0])
	}
}
