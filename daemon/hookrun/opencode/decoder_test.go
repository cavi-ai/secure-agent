package opencode

import (
	"encoding/json"
	"strings"
	"testing"
)

func completion(event, state, before, after string) []byte {
	return []byte(`{"type":"hook_completed","version":1,"harness":"opencode","protocol":"opencode-v2","id":"delivery-1","session_id":"session-1","ts":"2026-10-13T10:00:00Z","event":"` + event + `","state":"` + state + `","duration_ms":9,"before":` + before + `,"result":` + after + `}`)
}

func TestNativeOpenCodeMutations(t *testing.T) {
	for _, tc := range []struct {
		event, state, before, after, status string
		chars                               int64
	}{
		{"permission.evaluate", "completed", `{"effect":"allow"}`, `{"effect":"deny","message":"no 🌍"}`, "deny", 4},
		{"permission.evaluate", "completed", `{"effect":"deny","message":"earlier"}`, `{"effect":"deny","message":"earlier"}`, "ok", 0},
		{"permission.evaluate", "completed", `{"effect":"allow"}`, `{"effect":"ask","message":"private approval"}`, "ok", 0},
		{"session.context", "completed", `{"system":[{"type":"text","text":"original private prompt"}]}`, `{"system":[{"type":"text","text":"original private prompt"},{"type":"text","text":"héllo 🌍"}]}`, "inject", 7},
		{"session.context", "completed", `{"system":[{"type":"text","text":"original"}]}`, `{"system":[{"type":"text","text":"original"}]}`, "ok", 0},
		{"session.context", "completed", `{"system":[{"type":"text","text":"same"}]}`, `{"system":[{"type":"text","text":"same"},{"type":"text","text":"same"}]}`, "inject", 4},
		{"tool.execute.after", "completed", `null`, `{"status":"error","error":{"message":"private tool error"}}`, "ok", 0},
		{"tool.execute.before", "error", `null`, `null`, "error", 0},
		{"session.context", "cancelled", `null`, `null`, "cancelled", 0},
	} {
		t.Run(tc.event+"/"+tc.status, func(t *testing.T) {
			r, ok, err := (Decoder{}).Decode(completion(tc.event, tc.state, tc.before, tc.after))
			if err != nil || !ok || r.Harness != "opencode" || r.ID != "opencode:delivery-1" || r.Status != tc.status || r.Chars != tc.chars {
				t.Fatalf("record=%+v %v %v", r, ok, err)
			}
			data, _ := json.Marshal(r)
			if tc.event == "session.context" && tc.state == "completed" && (r.Evidence == nil || r.Evidence.ContextChars == nil || *r.Evidence.ContextChars != tc.chars || !r.Evidence.CharsKnown) {
				t.Fatalf("lost measured context: %+v", r)
			}
			if strings.Contains(string(data), "private") || strings.Contains(string(data), "héllo") {
				t.Fatal("native event content persisted")
			}
		})
	}
}

func TestOpenCodeRejectsMissingSnapshotsAndWrongProtocol(t *testing.T) {
	for _, line := range [][]byte{
		completion("session.context", "completed", `null`, `{"system":[]}`),
		completion("session.context", "completed", `{}`, `{"system":[{"type":"text","text":"private original"}]}`),
		completion("permission.evaluate", "completed", `{"effect":"allow"}`, `{"effect":"future"}`),
		[]byte(strings.Replace(string(completion("tool.execute.after", "completed", `null`, `null`)), `"opencode-v2"`, `"opencode-v1"`, 1)),
	} {
		if _, _, err := (Decoder{}).Decode(line); err == nil {
			t.Fatal("invalid mutation envelope accepted")
		}
	}
}
