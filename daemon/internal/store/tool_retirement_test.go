package store

import (
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"testing"
	"time"
)

func TestToolRetirementDoesNotOverwriteCompletion(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	e := event.Event{Kind: event.KindToolCall, TS: time.Now(), SessionID: "s", CallID: "a", ToolName: "read", ToolStatus: "ok", DurationMs: 42}
	s.PutEvent(e)
	e.ToolStatus = "incomplete"
	e.DurationMs = 0
	s.PutEvent(e)
	rows := s.QueryEvents(EventFilter{Limit: 10})
	if len(rows) != 1 || rows[0].ToolStatus != "ok" || rows[0].DurationMs != 42 {
		t.Fatal("retirement overwrote completed tool")
	}
}
