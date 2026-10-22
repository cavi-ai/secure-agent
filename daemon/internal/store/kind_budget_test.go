package store

import (
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// A plugin action is a hook-reported tool use: its budget holds as many as the
// transcript tool calls it mirrors, so a day of agent work is never evicted
// sooner than its tool calls are.
func TestPluginActionBudgetMatchesToolCalls(t *testing.T) {
	if pa, tc := kindBudget(int(event.KindPluginAction)), kindBudget(int(event.KindToolCall)); pa < tc {
		t.Fatalf("plugin-action budget %d < tool_call budget %d", pa, tc)
	}
}
