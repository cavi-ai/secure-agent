package event

import (
	"encoding/json"
	"testing"
	"time"
)

// Contract tests: event.Event is the wire type the web console (app.js) and
// the Swift menubar (Models.swift) parse by field name. A renamed or re-typed
// JSON key silently breaks both UIs — these tests are the tripwire.

func TestKindStringMappingIsStable(t *testing.T) {
	// The console and store label events by these strings; renumbering the
	// iota block or renaming a label corrupts every persisted row.
	want := map[Kind]string{
		KindFileOpen:      "file-open",
		KindFileWrite:     "file-write",
		KindFileDelete:    "file-delete",
		KindExec:          "exec",
		KindTCCModify:     "tcc-modify",
		KindConnOpen:      "conn-open",
		KindConnClose:     "conn-close",
		KindTranscriptHit: "transcript-hit",
		KindPluginAction:  "plugin-action",
		KindProxyHit:      "proxy-hit",
		KindGuardPrompt:   "guard-prompt",
		KindGuardResolved: "guard-resolved",
		KindToolCall:      "tool-call",
		KindTurn:          "turn",
		KindModelCall:     "model-call",
	}
	if len(want) != 15 {
		t.Fatalf("contract covers %d kinds; a new Kind must extend this test", len(want))
	}
	for k, s := range want {
		if k.String() != s {
			t.Errorf("Kind(%d).String() = %q, want %q", int(k), k.String(), s)
		}
	}
	if Kind(999).String() != "unknown" {
		t.Error("out-of-range Kind must render as unknown, not panic or empty")
	}
}

func TestEventJSONFieldNamesAreStable(t *testing.T) {
	ts := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	ev := Event{
		Kind:       KindConnOpen,
		TS:         ts,
		PID:        42,
		ExePath:    "/usr/local/bin/claude",
		SessionID:  "sess-1",
		Path:       "/tmp/x",
		RemoteHost: "api.anthropic.com",
		RemotePort: 443,
		Detail:     "rule-id",
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"kind", "ts", "pid", "exe_path", "session_id", "path", "remote_host", "remote_port", "detail"} {
		if _, ok := m[key]; !ok {
			t.Errorf("marshaled Event missing wire key %q: %s", key, raw)
		}
	}
	if len(m) != 9 {
		t.Errorf("Event gained or lost wire keys: %s", raw)
	}

	var back Event
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back != ev {
		t.Errorf("round trip mismatch: %+v vs %+v", back, ev)
	}
}

func TestEventOmitsEmptyOptionalFields(t *testing.T) {
	// The console treats presence of optional keys as meaningful; zero values
	// must stay absent so e.g. an empty session_id never renders.
	raw, err := json.Marshal(Event{Kind: KindConnClose, TS: time.Now(), PID: 1})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"exe_path", "session_id", "path", "remote_host", "remote_port", "detail",
		"tool", "tool_status", "duration_ms", "model", "tokens_in", "tokens_out", "cost_usd"} {
		if _, ok := m[key]; ok {
			t.Errorf("optional key %q must be omitted when empty: %s", key, raw)
		}
	}
}

// Trace fields round-trip: a model_call keeps model, tokens and cost; a
// tool_call keeps name, status, duration.
func TestEventTraceFieldsRoundTrip(t *testing.T) {
	ev := Event{
		Kind: KindModelCall, TS: time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC),
		SessionID: "s1", Model: "claude-sonnet-5",
		TokensIn: 46220, TokensOut: 8, CostUSD: 0.000139,
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"model", "tokens_in", "tokens_out", "cost_usd"} {
		if _, ok := m[key]; !ok {
			t.Errorf("model_call missing wire key %q: %s", key, raw)
		}
	}
	var back Event
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.Model != ev.Model || back.TokensIn != ev.TokensIn || back.CostUSD != ev.CostUSD {
		t.Errorf("round trip mismatch: %+v", back)
	}

	tc := Event{Kind: KindToolCall, TS: time.Now(), SessionID: "s1", ToolName: "Bash", ToolStatus: "ok", DurationMs: 31000}
	raw2, _ := json.Marshal(tc)
	var back2 Event
	if err := json.Unmarshal(raw2, &back2); err != nil {
		t.Fatal(err)
	}
	if back2.ToolName != "Bash" || back2.DurationMs != 31000 || back2.ToolStatus != "ok" {
		t.Errorf("tool_call round trip mismatch: %+v", back2)
	}
}
