package api

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestHookEvidenceEndpointBoundsScopeAndMeasurements(t *testing.T) {
	st := testStore(t)
	now := time.Now().UTC()
	for i := 0; i < 103; i++ {
		e := event.Event{Kind: event.KindHookRun, SessionID: "s", CallID: fmt.Sprintf("run-%03d", i), TS: now.Add(-time.Duration(i+1) * time.Second), HookHarness: "hermes", ToolName: "pre_tool_call", ToolStatus: "error", HookEvidence: &hookrun.Evidence{HandlerID: "h", ConfigID: "c", ReasonCode: "timeout", DurationKnown: true}}
		if _, err := st.PutEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range []event.Event{
		{Kind: event.KindHookRun, SessionID: "other", CallID: "foreign-session", TS: now, HookHarness: "hermes", ToolName: "pre_tool_call", ToolStatus: "ok", HookEvidence: &hookrun.Evidence{HandlerID: "h", ConfigID: "c"}},
		{Kind: event.KindHookRun, SessionID: "s", CallID: "foreign-config", TS: now, HookHarness: "hermes", ToolName: "pre_tool_call", ToolStatus: "ok", HookEvidence: &hookrun.Evidence{HandlerID: "h", ConfigID: "other"}},
		{Kind: event.KindHookRun, SessionID: "s", CallID: "legacy", TS: now, HookHarness: "claude", ToolName: "PreToolUse:Bash", Detail: "guard.py", ToolStatus: "cancelled"},
	} {
		if _, err := st.PutEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	sock := fmt.Sprintf("/tmp/sa_hook_evidence_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	a := newTestAPI(Deps{SocketPath: sock, Store: st, Status: func() Status { return Status{Running: true} }})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Serve(ctx) }()
	defer func() { cancel(); <-done }()
	waitForSocket(t, sock)
	cl := unixClient(sock)
	path := "http://unix/sessions/s/hook-evidence?harness=hermes&event=pre_tool_call&handler_id=h&config_id=c"
	resp, err := cl.Get(path)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("evidence unavailable: %v %v", resp, err)
	}
	var page struct {
		Truncated bool
		Rows      []struct {
			ID         string
			Status     string
			DurationMs *int64 `json:"duration_ms"`
			Chars      *int64
			Evidence   *hookrun.Evidence
		}
	}
	decodeInto(t, resp, &page)
	if !page.Truncated || len(page.Rows) != 100 || page.Rows[0].ID != "run-000" || page.Rows[0].DurationMs == nil || *page.Rows[0].DurationMs != 0 || page.Rows[0].Chars != nil || page.Rows[0].Evidence.ReasonCode != "timeout" {
		t.Fatalf("unbounded or measurements changed: %+v", page)
	}
	resp, err = cl.Get("http://unix/sessions/s/hook-evidence?harness=claude&event=PreToolUse&script=guard.py")
	if err != nil {
		t.Fatal(err)
	}
	page.Rows = nil
	decodeInto(t, resp, &page)
	if page.Truncated || len(page.Rows) != 1 || page.Rows[0].ID != "legacy" || page.Rows[0].Status != "cancelled" || page.Rows[0].DurationMs != nil || page.Rows[0].Chars != nil {
		t.Fatalf("legacy zero became a measurement: %+v", page)
	}
	if _, err := st.PutEvent(event.Event{Kind: event.KindHookRun, SessionID: "s", CallID: "tool-specific", TS: now.Add(-time.Second), HookHarness: "hermes", ToolName: "pre_tool_call:Read", ToolStatus: "cancelled", HookEvidence: &hookrun.Evidence{HandlerID: "h", ConfigID: "c"}}); err != nil {
		t.Fatal(err)
	}
	resp, err = cl.Get(path + "&event_scope=exact")
	if err != nil {
		t.Fatal(err)
	}
	page.Rows = nil
	decodeInto(t, resp, &page)
	if len(page.Rows) != 100 || page.Rows[0].ID != "run-000" {
		t.Fatalf("exact event combined another tool event: %+v", page)
	}
	resp, err = cl.Get("http://unix/sessions/s/hook-evidence?harness=hermes&event=pre_tool_call%3ARead&handler_id=h&config_id=c&event_scope=exact")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("exact tool event unavailable: %v %v", resp, err)
	}
	page.Rows = nil
	decodeInto(t, resp, &page)
	if len(page.Rows) != 1 || page.Rows[0].ID != "tool-specific" {
		t.Fatalf("exact tool event lost: %+v", page)
	}
	for _, query := range []string{"", "harness=other&event=x", "harness=hermes&event=x&handler_id=" + url.QueryEscape("/private/input"), "harness=hermes&event=x&limit=100000", "harness=hermes&event=x&event=y", "harness=hermes&event=x&since=2020-01-01T00:00:00Z", "harness=hermes&event=x&extra=%ZZ"} {
		resp, err := cl.Get("http://unix/sessions/s/hook-evidence?" + query)
		if err != nil {
			t.Fatal(err)
		}
		code := resp.StatusCode
		resp.Body.Close()
		if code != 400 {
			t.Fatalf("invalid query accepted: %q: %d", query, code)
		}
	}
	if h := st.WriteHealth(); len(h.ReadActive) != 0 {
		t.Fatalf("invalid query invented a storage failure: %+v", h)
	}
	verifyPath := path + "&event_scope=exact&verify_after=" + url.QueryEscape(now.Add(-time.Second).Format(time.RFC3339Nano))
	readVerification := func() string {
		t.Helper()
		resp, err := cl.Get(verifyPath)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			t.Fatalf("repair verification status=%d", resp.StatusCode)
		}
		var page struct {
			Verification struct {
				State  string
				RunIDs []string `json:"run_ids"`
			}
		}
		decodeInto(t, resp, &page)
		return page.Verification.State
	}
	if got := readVerification(); got != "configuration-changed" {
		t.Fatalf("configuration change lost: %s", got)
	}
	for _, e := range []event.Event{
		{Kind: event.KindHookRun, SessionID: "s", CallID: "new-success", TS: now.Add(time.Nanosecond), HookHarness: "hermes", ToolName: "pre_tool_call", ToolStatus: "ok", HookEvidence: &hookrun.Evidence{HandlerID: "h", ConfigID: "c"}},
		{Kind: event.KindHookRun, SessionID: "other", CallID: "foreign-failure", TS: now.Add(2 * time.Nanosecond), HookHarness: "hermes", ToolName: "pre_tool_call", ToolStatus: "error", HookEvidence: &hookrun.Evidence{HandlerID: "h", ConfigID: "c"}},
		{Kind: event.KindHookRun, SessionID: "s", CallID: "foreign-handler", TS: now.Add(2 * time.Nanosecond), HookHarness: "hermes", ToolName: "pre_tool_call", ToolStatus: "error", HookEvidence: &hookrun.Evidence{HandlerID: "different", ConfigID: "c"}},
	} {
		if _, err := st.PutEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	if got := readVerification(); got != "successful-completion" {
		t.Fatalf("foreign scope changed verification: %s", got)
	}
	for _, query := range []string{
		"harness=hermes&event=x&event_scope=exact&handler_id=h&verify_after=invalid",
		"harness=hermes&event=x&event_scope=exact&verify_after=" + url.QueryEscape(now.Format(time.RFC3339Nano)),
		"harness=hermes&event=x&handler_id=h&verify_after=" + url.QueryEscape(now.Format(time.RFC3339Nano)),
	} {
		resp, err := cl.Get("http://unix/sessions/s/hook-evidence?" + query)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatalf("invalid verification admitted: %d", resp.StatusCode)
		}
	}
}
