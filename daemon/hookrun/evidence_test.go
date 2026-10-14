package hookrun

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestEvidenceContract(t *testing.T) {
	zero := int64(0)
	r := Record{Type: "hook_run", Version: 2, Harness: "hermes", SessionID: "s", ID: "r", TS: time.Now().UTC(), Event: "pre_tool_call", Status: "error",
		Evidence: &Evidence{HandlerID: "handler-1", ConfigID: "revision-1", OperationID: "action-1", ExecutionMode: "foreground", ReasonCode: "timeout", ControlRole: "security", ActionOutcome: "stopped", DurationKnown: true, CharsKnown: true, ContextChars: &zero}}
	b, _ := json.Marshal(r)
	got, ok, err := DecodeRecord(b)
	if err != nil || !ok || got.Evidence == nil || !got.Evidence.DurationKnown || got.Evidence.ContextChars == nil || *got.Evidence.ContextChars != 0 {
		t.Fatalf("lost known zero or attribution: %+v %v", got, err)
	}
	for _, pair := range [][2]string{{`"handler-1"`, `"/private/path"`}, {`"foreground"`, `"maybe"`}, {`"timeout"`, `"secret text"`}, {`"stopped"`, `"allowed?"`}, {`"security"`, `"guard.py"`}, {`"context_chars":0`, `"context_chars":-1`}} {
		_, _, err := DecodeRecord([]byte(strings.Replace(string(b), pair[0], pair[1], 1)))
		if err == nil || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "secret") {
			t.Fatalf("invalid evidence accepted or disclosed: %v", err)
		}
	}
	for _, pair := range [][2]string{{`"duration_ms":0,`, ""}, {`"chars":0,`, ""}, {`"duration_ms":0`, `"duration_ms":null`}, {`"chars":0`, `"chars":null`}} {
		if _, _, err := DecodeRecord([]byte(strings.Replace(string(b), pair[0], pair[1], 1))); err == nil {
			t.Fatal("missing measurement became known zero")
		}
	}
}
