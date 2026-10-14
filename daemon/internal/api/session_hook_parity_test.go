package api

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

// Native fixtures exercise normalization, the real collector, SQLite and HTTP.
// Codex cancellation uses the normalized contract: its native completion
// decoder does not claim a cancellation status absent from that protocol.
func TestHookOutcomesAcrossHarnessesReachSessionAPI(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".claude", "projects", "repo", "session.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	st := testStore(t)
	b := bus.New(16)
	defer b.Close()
	sub := b.Subscribe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scanner := collect.NewTranscriptScanner(b, []string{path})
	scanner.OffsetStatePath = filepath.Join(root, "offsets.json")
	ready := make(chan struct{}, 1)
	scanner.OnCheckpointWrite = func(err error) {
		if err == nil {
			select {
			case ready <- struct{}{}:
			default:
			}
		}
	}
	done := make(chan error, 1)
	go func() { done <- scanner.Run(ctx) }()
	defer func() { cancel(); <-done }()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("collector did not seed source")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sock := fmt.Sprintf("/tmp/sa_hook_parity_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	a := newTestAPI(Deps{SocketPath: sock, Store: st, Status: func() Status { return Status{Running: true} }})
	apiDone := make(chan error, 1)
	go func() { apiDone <- a.Serve(ctx) }()
	defer func() { cancel(); <-apiDone }()
	waitForSocket(t, sock)
	cl := unixClient(sock)
	base := time.Now().UTC().Truncate(time.Second).Add(-30 * time.Second)
	for _, harness := range []string{"claude", "codex", "openclaw", "hermes", "opencode"} {
		t.Run(harness, func(t *testing.T) {
			session := harness + "-parity"
			if err := st.UpsertSession(model.Session{ID: session, Harness: harness, StartedAt: base.Add(-time.Minute), LastSeenAt: base, Status: model.SessionActive}); err != nil {
				t.Fatal(err)
			}
			var handler string
			appendRun := func(status, id, scope string, ts time.Time, measured bool, wantChange bool) {
				t.Helper()
				line := parityCompletion(t, harness, status, id, scope, handler, ts, measured)
				if _, err := f.Write(append(line, '\n')); err != nil {
					t.Fatal(err)
				}
				select {
				case e := <-sub:
					if e.Kind != event.KindHookRun || e.ToolStatus != status || e.SessionID != scope {
						t.Fatalf("outcome changed at collection: %+v", e)
					}
					if e.HookEvidence != nil {
						handler = e.HookEvidence.HandlerID
					}
					if w, err := st.PutEvent(e); err != nil || w.Changed != wantChange {
						t.Fatalf("deduplication: %+v %v", w, err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("completion did not reach collector")
				}
			}
			overview := func() SessionOverview {
				t.Helper()
				resp, err := cl.Get("http://unix/sessions/" + session + "/overview")
				if err != nil || resp.StatusCode != 200 {
					t.Fatalf("overview: %v %v", resp, err)
				}
				var out SessionOverview
				decodeInto(t, resp, &out)
				return out
			}
			for i := 0; i < 3; i++ {
				appendRun("error", fmt.Sprintf("failure-%d", i), session, base.Add(time.Duration(i)*time.Second), false, true)
			}
			appendRun("error", "failure-0", session, base, false, false)
			h := overview().HookHealth
			if h == nil || h.ObservedRuns != 3 {
				t.Fatalf("assessment: %+v", h)
			}
			if harness == "claude" {
				if len(h.Findings) != 0 || h.UnattributedRuns != 3 {
					t.Fatal("transcript metadata invented stable handler identity")
				}
			} else if len(h.Findings) != 1 || h.Findings[0].Kind != "execution-errors" || h.Findings[0].Count != 3 || !h.Findings[0].NeedsAction {
				t.Fatalf("equivalent failures did not produce repair finding: %+v", h)
			}
			appendRun("cancelled", "cancelled", session, base.Add(4*time.Second), false, true)
			if h := overview().HookHealth; h == nil || len(h.Findings) != 0 {
				t.Fatalf("cancellation counted as another failure: %+v", h)
			}
			appendRun("ok", "success", session, base.Add(5*time.Second), true, true)
			block := "block"
			if harness == "claude" || harness == "opencode" {
				block = "deny"
			}
			appendRun(block, "block", session, base.Add(6*time.Second), false, true)
			appendRun(block, "block", session+"-other", base.Add(6*time.Second), false, true)
			resp, err := cl.Get("http://unix/sessions/" + session + "/hooks")
			if err != nil {
				t.Fatal(err)
			}
			var rows []store.HookSummary
			decodeInto(t, resp, &rows)
			if len(rows) != 1 || rows[0].Runs != 6 || rows[0].Errors != 3 || rows[0].Cancelled != 1 || rows[0].Blocks != 1 {
				t.Fatalf("outcomes mixed, duplicated or crossed sessions: %+v", rows)
			}
			wantSamples := int64(1)
			if harness == "claude" {
				wantSamples = 0
			} // Legacy transcript zero is unknown.
			if rows[0].DurationSamples != wantSamples || rows[0].TotalMs != 0 {
				t.Fatalf("unknown became measured zero: %+v", rows[0])
			}
			if h := overview().HookHealth; h == nil || len(h.Findings) != 0 {
				t.Fatalf("expected block became repair finding: %+v", h)
			}
		})
	}
}

func parityCompletion(t *testing.T, harness, status, id, session, handler string, ts time.Time, measured bool) []byte {
	t.Helper()
	if harness == "claude" {
		typeName := map[string]string{"ok": "hook_success", "error": "hook_non_blocking_error", "cancelled": "hook_cancelled", "deny": "hook_success"}[status]
		attachment := map[string]any{"type": typeName, "hookName": "PreToolUse", "command": "guard.py"}
		if measured {
			attachment["durationMs"] = 0
		}
		if status == "deny" {
			attachment["stdout"] = `{"hookSpecificOutput":{"permissionDecision":"deny"}}`
		}
		data, _ := json.Marshal(map[string]any{"type": "attachment", "uuid": id, "sessionId": session, "timestamp": ts.Format(time.RFC3339Nano), "attachment": attachment})
		return data
	}
	if harness == "codex" && status == "cancelled" {
		data, _ := json.Marshal(hookrun.Record{Type: "hook_run", Version: 2, Harness: harness, ID: "codex:" + id, SessionID: session, TS: ts, Event: "PreToolUse", Status: status, Evidence: &hookrun.Evidence{HandlerID: handler}})
		return data
	}
	var input map[string]any
	var decoder hookrun.Decoder
	if harness == "codex" {
		run := map[string]any{"id": "native-handler", "eventName": "preToolUse", "status": map[string]string{"ok": "completed", "error": "failed", "block": "blocked"}[status], "completedAt": ts.Unix()}
		if measured {
			run["durationMs"] = 0
		}
		input = map[string]any{"id": id, "notification": map[string]any{"method": "hook/completed", "params": map[string]any{"threadId": session, "run": run}}}
		decoder = codex.Decoder{}
	} else {
		state := status
		if status == "ok" || status == "block" || status == "deny" {
			state = "completed"
		}
		input = map[string]any{"type": "hook_completed", "version": 2, "harness": harness, "id": id, "session_id": session, "ts": ts.Format(time.RFC3339Nano), "state": state, "evidence": map[string]any{"handler_id": "handler-1"}}
		if measured {
			input["duration_ms"] = 0
		}
		switch harness {
		case "openclaw":
			input["event"], input["result"], decoder = "before_tool_call", map[string]any{"block": status == "block"}, openclaw.Decoder{}
		case "hermes":
			result := map[string]any{}
			if status == "block" {
				result["action"], result["message"] = "block", "blocked"
			}
			input["event"], input["result"], decoder = "pre_tool_call", result, hermes.Decoder{}
		case "opencode":
			effect := "allow"
			if status == "deny" {
				effect = "deny"
			}
			input["event"], input["protocol"], input["before"], input["result"], decoder = "permission.evaluate", "opencode-v2", map[string]any{"effect": "allow"}, map[string]any{"effect": effect}, opencode.Decoder{}
		}
	}
	data, _ := json.Marshal(input)
	r, ok, err := decoder.Decode(data)
	if err != nil || !ok {
		t.Fatalf("native fixture: %s %v", data, err)
	}
	data, _ = json.Marshal(r)
	return data
}
