package openclaw

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
)

func completion(event, state, result string) []byte {
	return []byte(`{"type":"hook_completed","version":1,"harness":"openclaw","id":"delivery-1","session_id":"session-1","ts":"2026-10-13T10:00:00Z","event":"` + event + `","state":"` + state + `","duration_ms":9,"result":` + result + `}`)
}

func TestNativeOpenClawResults(t *testing.T) {
	for _, tc := range []struct {
		event, state, result, status string
		chars                        int64
	}{
		{"before_tool_call", "completed", `{"block":true,"blockReason":"no 🌍","params":{"secret":"private args"}}`, "block", 4},
		{"before_tool_call", "completed", `{"requireApproval":{"description":"private reason"}}`, "ok", 0},
		{"before_prompt_build", "completed", `{"prependContext":"héllo","appendSystemContext":"🌍","systemPrompt":"x"}`, "inject", 7},
		{"message_sending", "completed", `{"cancel":true}`, "block", 0},
		{"before_agent_finalize", "completed", `{"action":"revise","retry":{"instruction":"retry"},"reason":"private reason"}`, "block", 5},
		{"agent_end", "completed", `{"error":"underlying agent failed"}`, "ok", 0},
		{"before_tool_call", "error", `{"block":true,"blockReason":"private error"}`, "error", 0},
		{"before_prompt_build", "cancelled", `null`, "cancelled", 0},
	} {
		t.Run(tc.event+"/"+tc.state+"/"+tc.status, func(t *testing.T) {
			var decoder hookrun.Decoder = Decoder{}
			r, ok, err := decoder.Decode(completion(tc.event, tc.state, tc.result))
			if err != nil || !ok || r.Harness != "openclaw" || r.ID != "openclaw:delivery-1" || r.Status != tc.status || r.Chars != tc.chars || r.DurationMs != 9 {
				t.Fatalf("record = %+v, %v, %v", r, ok, err)
			}
			data, _ := json.Marshal(r)
			if tc.event == "before_prompt_build" && tc.state == "completed" && (r.Evidence == nil || r.Evidence.ContextChars == nil || *r.Evidence.ContextChars != tc.chars || !r.Evidence.CharsKnown) {
				t.Fatalf("lost measured context: %+v", r)
			}
			if strings.Contains(string(data), "private") || strings.Contains(string(data), "héllo") {
				t.Fatal("native text persisted")
			}
		})
	}
}

func TestOpenClawRejectsMalformedAndForeignCompletions(t *testing.T) {
	for _, line := range [][]byte{
		completion("before_tool_call", "running", `null`),
		completion("before_tool_call", "completed", `{"block":"false"}`),
		[]byte(strings.Replace(string(completion("before_tool_call", "completed", `null`)), `"openclaw"`, `"hermes"`, 1)),
	} {
		if _, _, err := (Decoder{}).Decode(line); err == nil {
			t.Fatal("invalid completion accepted")
		}
	}
	if _, ok, err := (Decoder{}).Decode([]byte(`{"type":"tool_completed","status":"error"}`)); ok || err != nil {
		t.Fatalf("tool result mistaken for hook: %v %v", ok, err)
	}
}
