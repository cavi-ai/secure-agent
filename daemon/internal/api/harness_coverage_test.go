package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestHookActivityCannotCoverAnotherHarness(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	st := testStore(t)
	now := time.Now()
	st.UpsertSession(model.Session{ID: "claude-session", Harness: "claude", StartedAt: now, LastSeenAt: now})
	st.PutEvent(event.Event{Kind: event.KindPluginAction, TS: now, SessionID: "claude-session"})
	a := newTestAPI("", st, nil, func() Status {
		return Status{Running: true, ActiveAgents: 2, Agents: []AgentSummary{{PID: 10, Name: "claude"}, {PID: 20, Name: "cursor"}}}
	})
	p := a.computePosture()
	for _, item := range p.CoverageItems {
		if item.Kind == "harness_uncovered" && strings.Contains(item.Title, "cursor") {
			return
		}
	}
	t.Fatalf("Claude activity hid Cursor's missing guard evidence: %+v", p.CoverageItems)
}

func TestCodexDoesNotRequireClaudeGuardRegistration(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	a := newTestAPI("", testStore(t), nil, func() Status {
		return Status{Running: true, ActiveAgents: 1, Agents: []AgentSummary{{PID: 20, Name: "codex"}}}
	})
	p := a.computePosture()
	for _, item := range p.CoverageItems {
		if item.Kind == "guard_hook_unregistered" || item.Kind == "harness_uncovered" {
			t.Fatalf("Codex incorrectly requires a supported Claude/Cursor hook: %+v", item)
		}
	}
	rep := a.doctorReport(time.Now())
	for _, id := range []string{"hook-registered", "hook-active"} {
		if c := doctorCheckByID(t, rep, id); c.State != doctorSkip {
			t.Fatalf("irrelevant hook check should skip: %+v", c)
		}
	}
}

func TestStatusSeparatesHarnessTraceAndGuardCapabilities(t *testing.T) {
	st := testStore(t)
	now := time.Now()
	st.UpsertSession(model.Session{ID: "codex-session", Harness: "codex", StartedAt: now, LastSeenAt: now})
	st.PutEvent(event.Event{Kind: event.KindToolCall, TS: now, SessionID: "codex-session", ToolName: "exec"})
	a := newTestAPI("", st, nil, func() Status {
		return Status{Running: true, ActiveAgents: 2, Agents: []AgentSummary{
			{PID: 10, Name: "claude"}, {PID: 11, Name: "claude", RootPID: 10},
			{PID: 20, Name: "codex"}, {PID: 30, Name: "ollama", Kind: "infra"},
		}}
	})
	w := httptest.NewRecorder()
	a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/status", nil))
	var body struct {
		Coverage struct {
			Harnesses []struct {
				Name           string `json:"name"`
				GuardSupported bool   `json:"guard_supported"`
				TraceSupported bool   `json:"trace_supported"`
				HookLastSeen   string `json:"hook_last_seen"`
				TraceLastSeen  string `json:"trace_last_seen"`
			} `json:"harnesses"`
		} `json:"coverage"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Coverage.Harnesses) != 2 {
		t.Fatalf("missing distinct harness capabilities: %s", w.Body.String())
	}
	claude, codex := body.Coverage.Harnesses[0], body.Coverage.Harnesses[1]
	if claude.Name != "claude" || !claude.GuardSupported || !claude.TraceSupported || claude.HookLastSeen != "" {
		t.Fatalf("Claude guard capability confused with activity: %+v", claude)
	}
	if codex.Name != "codex" || codex.GuardSupported || !codex.TraceSupported || codex.TraceLastSeen == "" {
		t.Fatalf("Codex tracing confused with guarding: %+v", codex)
	}
}
