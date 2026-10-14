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

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
	"github.com/cavi-ai/secure-agent/daemon/hookrun/codex"
	"github.com/cavi-ai/secure-agent/daemon/hookrun/hermes"
	"github.com/cavi-ai/secure-agent/daemon/hookrun/openclaw"
	"github.com/cavi-ai/secure-agent/daemon/hookrun/opencode"
	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
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

func TestHookEvidenceReachesOverviewAndAttention(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_hh_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	st := testStore(t)
	now := time.Now().UTC()
	if err := st.UpsertSession(model.Session{ID: "s", Harness: "hermes", StartedAt: now.Add(-time.Hour), LastSeenAt: now, Status: model.SessionActive}); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "activity.jsonl")
	if err := os.WriteFile(logPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	b := bus.New(16)
	defer b.Close()
	sub := b.Subscribe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scanner := collect.NewTranscriptScanner(b, []string{logPath})
	go scanner.Run(ctx)
	time.Sleep(250 * time.Millisecond)
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		input := fmt.Sprintf(`{"type":"hook_completed","version":2,"harness":"hermes","session_id":"s","id":"delivery-%d","ts":%q,"event":"pre_tool_call","script":"guard.py","state":"error","duration_ms":0,"evidence":{"handler_id":"h","config_id":"c","reason_code":"timeout","control_role":"security","action_outcome":"proceeded"}}`, i, now.Add(time.Duration(i-5)*time.Second).Format(time.RFC3339Nano))
		r, ok, err := (hermes.Decoder{}).Decode([]byte(input))
		if err != nil || !ok {
			t.Fatalf("decode: %v", err)
		}
		data, _ := json.Marshal(r)
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
			if _, err := st.PutEvent(e); err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("missing forwarded run")
		}
	}
	a := newTestAPI(Deps{SocketPath: sock, Store: st, Killer: &fakeKiller{}, Status: func() Status { return Status{Running: true} }})
	go a.Serve(ctx)
	waitForSocket(t, sock)
	resp, err := unixClient(sock).Get("http://unix/sessions/s/overview")
	if err != nil {
		t.Fatal(err)
	}
	var overview SessionOverview
	decodeInto(t, resp, &overview)
	if overview.HookHealth == nil || !overview.HookHealth.Available || len(overview.HookHealth.Findings) != 1 || overview.HookHealth.Findings[0].Title != "Security hook repeatedly failed" {
		t.Fatalf("overview = %+v", overview)
	}
	resp, err = unixClient(sock).Get("http://unix/posture")
	if err != nil {
		t.Fatal(err)
	}
	var posture Posture
	decodeInto(t, resp, &posture)
	count := 0
	for _, g := range posture.Groups {
		for _, item := range g.Items {
			if item.Kind == "hook" {
				count++
				if item.SessionID != "s" || item.HookFinding == nil || item.HookFinding.ID != overview.HookHealth.Findings[0].ID {
					t.Fatalf("lost attribution: %+v", item)
				}
			}
		}
	}
	if count != 1 || posture.NeedsYou != 1 {
		t.Fatalf("attention=%+v", posture)
	}
	if err := st.EndSession("s", now); err != nil {
		t.Fatal(err)
	}
	resp, err = unixClient(sock).Get("http://unix/posture")
	if err != nil {
		t.Fatal(err)
	}
	decodeInto(t, resp, &posture)
	if posture.NeedsYou != 0 {
		t.Fatalf("ended session retained live repair attention: %+v", posture)
	}
}

// A host may retry a completion, while the same native handler can run more
// than once in a turn. Exercise the shared log, collector, SQLite and API.
func TestForwardedNativeHooksReachSessionAPI(t *testing.T) {
	adapters := []struct {
		name, event, result, extra string
		decoder                    hookrun.Decoder
	}{
		{"codex", "PreToolUse", "", "", codex.Decoder{}},
		{"openclaw", "before_tool_call", `{"block":true,"blockReason":"no"}`, "", openclaw.Decoder{}},
		{"hermes", "pre_tool_call", `{"action":"block","message":"no"}`, "", hermes.Decoder{}},
		{"opencode", "permission.evaluate", `{"effect":"deny","message":"no"}`, `,"protocol":"opencode-v2","before":{"effect":"allow"}`, opencode.Decoder{}},
	}
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
	for _, adapter := range adapters {
		for _, id := range []string{"delivery-1", "delivery-2", "delivery-1"} {
			line := `{"id":"` + id + `","notification":{"method":"hook/completed","params":{"threadId":"codex-thread","run":{"id":"same-handler","eventName":"preToolUse","status":"blocked","completedAt":1791882001,"durationMs":5,"entries":[{"kind":"feedback","text":"no"}]}}}}`
			if adapter.name != "codex" {
				line = `{"type":"hook_completed","version":1,"harness":"` + adapter.name + `","id":"` + id + `","session_id":"` + adapter.name + `-thread","ts":"2026-10-13T10:00:00Z","event":"` + adapter.event + `","state":"completed","duration_ms":5,"result":` + adapter.result + adapter.extra + `}`
			}
			r, ok, err := adapter.decoder.Decode([]byte(line))
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
	}
	// Native Codex identity alone must attribute repeated failures. No host
	// evidence mapping is supplied, and replayed delivery IDs stay idempotent.
	now := time.Now().UTC()
	if err := st.UpsertSession(model.Session{ID: "codex-repair", Harness: "codex", StartedAt: now.Add(-time.Minute), Status: model.SessionActive}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"native-0", "native-1", "native-2", "native-0"} {
		line := fmt.Sprintf(`{"id":%q,"notification":{"method":"hook/completed","params":{"threadId":"codex-repair","run":{"id":"pre-tool-use:0:/home/example/hooks.json","eventName":"preToolUse","status":"failed","completedAt":%d,"durationMs":5,"entries":[]}}}}`, id, now.Add(-5*time.Second).Unix())
		r, ok, err := (codex.Decoder{}).Decode([]byte(line))
		if err != nil || !ok {
			t.Fatalf("native decode: %v", err)
		}
		data, _ := json.Marshal(r)
		if _, err := f.Write(append(data, '\n')); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	for range 3*len(adapters) + 4 {
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
	for _, adapter := range adapters {
		id := adapter.name + "-thread"
		resp, err := unixClient(sock).Get("http://unix/sessions/" + id + "/hooks")
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("GET hooks: %v %v", resp, err)
		}
		var rows []store.HookSummary
		decodeInto(t, resp, &rows)
		if len(rows) != 1 || rows[0].Runs != 2 || rows[0].Blocks != 2 || rows[0].Chars != 4 || rows[0].TotalMs != 10 || rows[0].Event != adapter.event || rows[0].Script != "" {
			t.Fatalf("hook summary = %+v", rows)
		}
		timeline, err := st.QueryEvents(store.EventFilter{SessionID: id, Limit: 10})
		if err != nil || len(timeline) != 0 {
			t.Fatalf("hook leaked into timeline: %+v %v", timeline, err)
		}
	}
	resp, err := unixClient(sock).Get("http://unix/sessions/codex-repair/overview")
	if err != nil {
		t.Fatal(err)
	}
	var overview SessionOverview
	decodeInto(t, resp, &overview)
	if overview.HookHealth == nil || len(overview.HookHealth.Findings) != 1 {
		t.Fatalf("native identity did not reach findings: %+v", overview.HookHealth)
	}
	finding := overview.HookHealth.Findings[0]
	if finding.Kind != "execution-errors" || finding.Count != 3 || !strings.HasPrefix(finding.HandlerID, "codex-handler:") || finding.ConfigID != "" {
		t.Fatalf("native finding = %+v", finding)
	}
}
