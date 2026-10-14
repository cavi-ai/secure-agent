package collect

import (
	"github.com/cavi-ai/secure-agent/daemon/hookrun"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// hookRunEvent is the only mapping from the shared hook metadata contract to
// the daemon bus. Harness adapters own parsing; storage and the console do
// not need to know which transport or harness produced the completion.
func hookRunEvent(r hookrun.Record) event.Event {
	return event.Event{Kind: event.KindHookRun, TS: r.TS, SessionID: r.SessionID, CallID: r.ID,
		ToolName: r.Event, Detail: r.Script, ToolStatus: r.Status, DurationMs: r.DurationMs, Chars: r.Chars,
		HookHarness: r.Harness, HookEvidence: r.Evidence}
}
