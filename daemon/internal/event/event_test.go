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
	}
	if len(want) != 12 {
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
	for _, key := range []string{"exe_path", "session_id", "path", "remote_host", "remote_port", "detail"} {
		if _, ok := m[key]; ok {
			t.Errorf("optional key %q must be omitted when empty: %s", key, raw)
		}
	}
}
