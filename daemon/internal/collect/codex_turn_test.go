package collect

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

const codexTaskStarted = `{"timestamp":"2026-10-21T14:29:42.000Z","type":"event_msg","payload":{"type":"task_started","turn_id":"t1","model_context_window":258400}}`

// event_msg/task_started opens each Codex user turn: it becomes a turn on
// the rollout's session, and nothing before session_meta names one.
func TestCodexTaskStartedIsATurn(t *testing.T) {
	if evs, ok := NewCodexTracer("").ParseLine(codexTaskStarted); !ok || len(evs) != 0 {
		t.Fatalf("before session_meta: events %+v ok %v, want none", evs, ok)
	}
	tr := NewCodexTracer("")
	tr.ParseLine(`{"timestamp":"2026-10-21T14:29:41.000Z","type":"session_meta","payload":{"session_id":"s-1","cwd":"/repo"}}`)
	evs, ok := tr.ParseLine(codexTaskStarted)
	if !ok || len(evs) != 1 {
		t.Fatalf("events %+v ok %v, want one turn", evs, ok)
	}
	e := evs[0]
	if e.Kind != event.KindTurn || e.SessionID != "s-1" || !e.TS.Equal(time.Date(2026, 10, 21, 14, 29, 42, 0, time.UTC)) {
		t.Fatalf("turn = %+v", e)
	}
}
