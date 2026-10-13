package api

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// /sessions/{id}/hooks serves the session's hook totals; hook runs stay out
// of /sessions/{id}/timeline.
func TestSessionHooksEndpoint(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_hooks_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	st := testStore(t)
	now := time.Now()
	st.PutEvent(event.Event{Kind: event.KindToolCall, TS: now, SessionID: "s1", CallID: "t1", ToolName: "Bash", ToolStatus: "ok"})
	for i, status := range []string{"error", "error", "ok"} {
		st.PutEvent(event.Event{Kind: event.KindHookRun, TS: now.Add(time.Duration(i) * time.Second), SessionID: "s1",
			CallID: fmt.Sprintf("r%d", i), ToolName: "PreToolUse:Bash", Detail: "secret_guard.py", ToolStatus: status, DurationMs: 10})
	}
	st.PutEvent(event.Event{Kind: event.KindHookRun, TS: now, SessionID: "other", CallID: "r9", ToolName: "Stop", Detail: "stop.py", ToolStatus: "ok"})

	a := newTestAPI(Deps{SocketPath: sock, Store: st, Killer: &fakeKiller{}, Status: func() Status { return Status{Running: true} }})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)
	cl := unixClient(sock)

	resp, err := cl.Get("http://unix/sessions/s1/hooks")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("GET hooks: %v %v", resp, err)
	}
	var hooks []store.HookSummary
	decodeInto(t, resp, &hooks)
	if len(hooks) != 1 || hooks[0].Event != "PreToolUse" || hooks[0].Script != "secret_guard.py" ||
		hooks[0].Runs != 3 || hooks[0].Errors != 2 || hooks[0].TotalMs != 30 {
		t.Fatalf("hooks = %+v, want one secret_guard.py row with 3 runs, 2 errors", hooks)
	}

	resp, err = cl.Get("http://unix/sessions/s1/timeline")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("GET timeline: %v %v", resp, err)
	}
	var tl []event.Event
	decodeInto(t, resp, &tl)
	if len(tl) != 1 || tl[0].Kind != event.KindToolCall {
		t.Fatalf("timeline = %+v, want only the tool call", tl)
	}
}
