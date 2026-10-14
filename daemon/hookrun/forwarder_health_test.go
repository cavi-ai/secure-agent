package hookrun

import (
	"encoding/json"
	"strings"
	"testing"
)

const healthReportJSON = `{"type":"hook_forwarder","version":2,"harness":"codex","forwarder_id":"instance-1","sequence":1,"session_id":"s","ts":"2026-10-13T10:00:00Z","state":"error","pending":2,"delivery_failures":3,"dropped":1,"health":{"source_state":"connected","capture_error":"invalid-input","delivery_error":"recorder-unavailable","report_error":false,"outbox":{"persisted":1,"recovered":2,"error":"outbox-full"}}}`

func TestForwarderHealthContractAcrossHarnesses(t *testing.T) {
	for _, harness := range []string{"claude", "codex", "openclaw", "hermes", "opencode"} {
		t.Run(harness, func(t *testing.T) {
			input := strings.Replace(healthReportJSON, `"codex"`, `"`+harness+`"`, 1)
			r, ok, err := DecodeForwarderReport([]byte(input))
			if !ok || err != nil {
				t.Fatalf("structured report rejected: %v %v", ok, err)
			}
			data, err := json.Marshal(r)
			if err != nil || !strings.Contains(string(data), `"source_state":"connected"`) || !strings.Contains(string(data), `"persisted":1`) {
				t.Fatalf("diagnostics lost: %s %v", data, err)
			}
		})
	}
}

func TestForwarderHealthRejectsContradictionsAndUnsafeDetails(t *testing.T) {
	for _, change := range [][2]string{
		{`"version":2`, `"version":1`},
		{`"state":"error"`, `"state":"connected"`},
		{`"source_state":"connected"`, `"source_state":"healthy"`},
		{`"capture_error":"invalid-input"`, `"capture_error":"/private/input"`},
		{`"capture_error":"invalid-input"`, `"capture_error":null`},
		{`"delivery_error":"recorder-unavailable"`, `"delivery_error":"invalid-input"`},
		{`"delivery_error":"recorder-unavailable"`, `"delivery_error":null`},
		{`"error":"outbox-full"`, `"error":"private disk error"`},
		{`"error":"outbox-full"`, `"error":null`},
		{`"persisted":1`, `"persisted":3`},
		{`"persisted":1,`, ``},
		{`"recovered":2`, `"recovered":null`},
		{`"report_error":false,`, ``},
		{`"report_error":false`, `"report_error":null`},
		{`"health":{`, `"health":{"raw_error":"private text",`},
	} {
		_, ok, err := DecodeForwarderReport([]byte(strings.Replace(healthReportJSON, change[0], change[1], 1)))
		if !ok || err == nil || strings.Contains(err.Error(), "private") {
			t.Fatalf("invalid health accepted or leaked: %v %v (%s)", ok, err, change[0])
		}
	}
}
