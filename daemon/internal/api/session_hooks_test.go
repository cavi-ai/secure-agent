package api

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/hookrun/codex"
	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
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

// A host may retry a completion, while the same native handler can run more
// than once in a turn. Exercise the shared log, collector, SQLite and API.
func TestForwardedCodexHooksReachSessionAPI(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "activity.jsonl")
	if err := os.WriteFile(logPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	st := testStore(t)
	b := bus.New(16)
	defer b.Close()
	sub := b.Subscribe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scanner := collect.NewTranscriptScanner(b, []string{logPath})
	go scanner.Run(ctx)
	// The existing scanner starts at EOF for uncheckpointed source files.
	time.Sleep(250 * time.Millisecond)
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"delivery-1", "delivery-2", "delivery-1"} {
		line := `{"id":"` + id + `","notification":{"method":"hook/completed","params":{"threadId":"codex-thread","run":{"id":"same-handler","eventName":"preToolUse","status":"blocked","completedAt":1791882001,"durationMs":5,"entries":[{"kind":"feedback","text":"no"}]}}}}`
		r, ok, err := (codex.Decoder{}).Decode([]byte(line))
		if err != nil || !ok {
			t.Fatalf("decode=%v error=%v", ok, err)
		}
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(append(data, '\n')); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		select {
		case e := <-sub:
			if e.Kind != event.KindHookRun {
				t.Fatalf("event kind = %v", e.Kind)
			}
			if _, err := st.PutEvent(e); err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("forwarded completion did not reach collector")
		}
	}
	sock := fmt.Sprintf("/tmp/sa_codex_hooks_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	a := newTestAPI(Deps{SocketPath: sock, Store: st, Killer: &fakeKiller{}, Status: func() Status { return Status{Running: true} }})
	go a.Serve(ctx)
	waitForSocket(t, sock)
	resp, err := unixClient(sock).Get("http://unix/sessions/codex-thread/hooks")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("GET hooks: %v %v", resp, err)
	}
	var rows []store.HookSummary
	decodeInto(t, resp, &rows)
	if len(rows) != 1 || rows[0].Runs != 2 || rows[0].Blocks != 2 || rows[0].Chars != 4 || rows[0].TotalMs != 10 || rows[0].Event != "PreToolUse" || rows[0].Script != "" {
		t.Fatalf("hook summary = %+v", rows)
	}
	timeline, err := st.QueryEvents(store.EventFilter{SessionID: "codex-thread", Limit: 10})
	if err != nil || len(timeline) != 0 {
		t.Fatalf("hook leaked into timeline: %+v %v", timeline, err)
	}
	for _, row := range rows {
		if strings.Contains(row.Script, "same-handler") {
			t.Fatal("native handler id retained")
		}
	}
}
