package hookrun

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRecordContractRejectsInvalidMetadata(t *testing.T) {
	r := Record{Type: "hook_run", Version: 1, Harness: "codex", SessionID: "session-1", ID: "codex:delivery-1",
		TS: time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC), Event: "PreToolUse", Status: "inject", Chars: 7}
	data, _ := json.Marshal(r)
	for _, replacement := range [][2]string{
		{`"version":1`, `"version":2`},
		{`"harness":"codex"`, `"harness":"unknown"`},
		{`"event":"PreToolUse"`, `"event":"/home/private"`},
		{`"chars":7`, `"chars":-1`},
		{`"status":"inject"`, `"status":"running"`},
		{`"event":"PreToolUse"`, `"event":"PreToolUse","script":"C:private.py"`},
		{`"event":"PreToolUse"`, `"event":"PreToolUse","output":"private text"`},
	} {
		bad := strings.Replace(string(data), replacement[0], replacement[1], 1)
		_, ok, err := DecodeRecord([]byte(bad))
		if !ok || err == nil || strings.Contains(err.Error(), "private") {
			t.Fatalf("invalid contract: ok=%v err=%v", ok, err)
		}
	}
	decoded, ok, err := DecodeRecord(data)
	if err != nil || !ok || decoded != r {
		t.Fatalf("round trip = %+v, %v, %v", decoded, ok, err)
	}
}

func TestSharedContractAcrossHarnesses(t *testing.T) {
	var decoder Decoder = RecordDecoder{}
	for _, harness := range []string{"claude", "codex", "openclaw", "hermes", "opencode"} {
		for _, status := range []string{"ok", "inject", "deny", "block", "error", "cancelled"} {
			t.Run(harness+"/"+status, func(t *testing.T) {
				id, err := ExecutionID(harness, "completion-1")
				if err != nil {
					t.Fatal(err)
				}
				r := Record{Type: "hook_run", Version: 1, Harness: harness, SessionID: "session-1", ID: id,
					TS: time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC), Event: "before_tool", Status: status, DurationMs: 12, Chars: 7}
				data, err := json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
				got, ok, err := decoder.Decode(data)
				if err != nil || !ok || got != r {
					t.Fatalf("contract round trip = %+v, %v, %v", got, ok, err)
				}
			})
		}
	}
}

func TestExecutionIDRejectsMissingUnsafeAndOversizedIDs(t *testing.T) {
	for _, tc := range [][2]string{{"codex", ""}, {"", "completion-1"}, {"codex", "/home/private"}, {"codex", strings.Repeat("a", 256)}} {
		if _, err := ExecutionID(tc[0], tc[1]); err == nil {
			t.Fatal("invalid execution identity accepted")
		}
	}
	id, err := ExecutionID("codex", "completion-1")
	if err != nil || id != "codex:completion-1" {
		t.Fatalf("execution id = %q, %v", id, err)
	}
}
