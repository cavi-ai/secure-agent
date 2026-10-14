package forwarder_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
	"github.com/cavi-ai/secure-agent/daemon/hookrun/forwarder"
	"github.com/cavi-ai/secure-agent/daemon/hookrun/hermes"
	"github.com/cavi-ai/secure-agent/daemon/hookrun/openclaw"
	"github.com/cavi-ai/secure-agent/daemon/hookrun/opencode"
)

func TestNativeAdaptersShareCaptureFailuresAndRecovery(t *testing.T) {
	for _, tc := range []struct {
		harness, event, extra string
		decoder               hookrun.Decoder
	}{
		{"openclaw", "before_tool_call", "", openclaw.Decoder{}},
		{"hermes", "pre_tool_call", "", hermes.Decoder{}},
		{"opencode", "permission.evaluate", `,"protocol":"opencode-v2","before":{"effect":"allow"}`, opencode.Decoder{}},
	} {
		t.Run(tc.harness, func(t *testing.T) {
			c, err := forwarder.NewAdapter(forwarder.Config{Harness: tc.harness, Sender: &destination{}, Capacity: 1}, tc.decoder)
			if err != nil {
				t.Fatal(err)
			}
			_ = c.SetSourceState("connected")
			if _, err := c.Submit([]byte(`{"type":"hook_completed","private`)); hookrun.ErrorCode(err) != "invalid-input" {
				t.Fatalf("malformed input: %v", err)
			}
			if id, err := c.Submit([]byte(`{"type":"hook_started"}`)); id != "" || err != nil {
				t.Fatal("unrelated message became completion")
			}
			if h := snapshotHealth(t, c.Client); h.CaptureError != "invalid-input" {
				t.Fatal("unrelated message cleared capture error")
			}
			if _, err := c.Submit([]byte(fmt.Sprintf(`{"type":"hook_completed","version":99,"harness":%q}`, tc.harness))); hookrun.ErrorCode(err) != "unsupported-protocol" {
				t.Fatalf("unsupported envelope version: %v", err)
			}
			raw := fmt.Sprintf(`{"type":"hook_completed","version":1,"harness":%q,"id":"one","session_id":"s","ts":"2026-10-13T10:00:00Z","event":%q,"state":"completed","result":{"effect":"allow"}%s}`, tc.harness, tc.event, tc.extra)
			id, err := c.Submit([]byte(raw))
			if err != nil || id != tc.harness+":one" {
				t.Fatalf("capture: %q %v", id, err)
			}
			if h := snapshotHealth(t, c.Client); h.CaptureError != "" {
				t.Fatalf("successful admission did not clear capture failure: %+v", h)
			}
			if _, err := c.Submit([]byte(raw)); err != nil || c.Snapshot().Pending != 1 {
				t.Fatal("retry duplicated pending completion")
			}
			if tc.harness == "opencode" {
				if _, err := c.Submit([]byte(`{"type":"hook_completed","version":1,"harness":"opencode","id":"two","session_id":"s","ts":"2026-10-13T10:00:00Z","event":"permission.evaluate","state":"completed","protocol":"opencode-v1"}`)); hookrun.ErrorCode(err) != "unsupported-protocol" {
					t.Fatalf("unsupported protocol: %v", err)
				}
			}
		})
	}
	if _, err := forwarder.NewAdapter(forwarder.Config{Harness: "hermes", Sender: &destination{}}, nil); err == nil {
		t.Fatal("nil decoder accepted")
	}
}

func TestCodexLimitAppliesToNativeInputBeforeWrapping(t *testing.T) {
	c, err := forwarder.NewCodex(forwarder.Config{Sender: &destination{}})
	if err != nil {
		t.Fatal(err)
	}
	prefix := completion[:len(completion)-1] + `,"padding":"`
	input := []byte(prefix + strings.Repeat("x", 1024*1024-len(prefix)-2) + `"}`)
	if _, err := c.Submit(input); err != nil {
		t.Fatalf("valid native input below limit rejected by internal envelope: %v", err)
	}
	input = append(input, ' ')
	if _, err := c.Submit(input); hookrun.ErrorCode(err) != "invalid-input" {
		t.Fatalf("oversize native input accepted: %v", err)
	}
}
