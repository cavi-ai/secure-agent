package hookrun

import (
	"strings"
	"testing"
)

const forwarderJSON = `{"type":"hook_forwarder","version":1,"harness":"codex","forwarder_id":"instance-1","sequence":1,"session_id":"s","ts":"2026-10-13T10:00:00Z","state":"error","pending":2,"delivery_failures":3,"dropped":0}`

func TestForwarderContract(t *testing.T) {
	r, ok, err := DecodeForwarderReport([]byte(forwarderJSON))
	if !ok || err != nil || r.ForwarderID != "instance-1" || r.Pending != 2 {
		t.Fatalf("report=%+v %v %v", r, ok, err)
	}
	for _, change := range [][2]string{
		{`"version":1`, `"version":2`}, {`"forwarder_id":"instance-1"`, `"forwarder_id":"/private/value"`},
		{`"session_id":"s"`, `"session_id":"/private/value"`}, {`"harness":"codex"`, `"harness":"private-value"`},
		{`"sequence":1`, `"sequence":0`}, {`"pending":2`, `"pending":null`}, {`"pending":2,`, ``},
		{`"dropped":0`, `"dropped":-1`}, {`"dropped":0`, `"dropped":9007199254740992`},
		{`"state":"error"`, `"state":"healthy"`}, {`"state":"error"`, `"state":"error","output":"private-value"`},
	} {
		_, ok, err := DecodeForwarderReport([]byte(strings.Replace(forwarderJSON, change[0], change[1], 1)))
		if !ok || err == nil || strings.Contains(err.Error(), "private") {
			t.Fatalf("invalid report: %v %v", ok, err)
		}
	}
	for _, harness := range []string{"claude", "openclaw", "hermes", "opencode"} {
		if _, ok, err := DecodeForwarderReport([]byte(strings.Replace(forwarderJSON, `"codex"`, `"`+harness+`"`, 1))); !ok || err != nil {
			t.Fatalf("harness %s: %v", harness, err)
		}
	}
	if _, ok, err := DecodeForwarderReport([]byte(`{"type":"hook_run"}`)); ok || err != nil {
		t.Fatal("completion mistaken for report")
	}
}
