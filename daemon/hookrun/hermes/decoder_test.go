package hermes

import (
	"encoding/json"
	"strings"
	"testing"
)

func completion(event, state, result string) []byte {
	return []byte(`{"type":"hook_completed","version":1,"harness":"hermes","id":"delivery-1","session_id":"session-1","ts":"2026-10-13T10:00:00Z","event":"` + event + `","state":"` + state + `","duration_ms":9,"result":` + result + `}`)
}

func TestNativeHermesResults(t *testing.T) {
	for _, tc := range []struct {
		event, state, result, status string
		chars                        int64
	}{
		{"pre_tool_call", "completed", `{"action":"block","message":"no 🌍"}`, "block", 4},
		{"pre_tool_call", "completed", `{"action":"approve","message":"private approval"}`, "ok", 0},
		{"pre_tool_call", "completed", `{"action":"modify","args":{"secret":"private args"}}`, "ok", 0},
		{"pre_tool_call", "completed", `{"action":"block","message":""}`, "ok", 0},
		{"pre_llm_call", "completed", `{"context":"héllo 🌍"}`, "inject", 7},
		{"pre_llm_call", "completed", `"hello"`, "inject", 5},
		{"pre_llm_call", "completed", `{"context":"   "}`, "inject", 3},
		{"pre_llm_call", "completed", `"   "`, "ok", 0},
		{"pre_verify", "completed", `{"action":"continue","message":" retry "}`, "block", 5},
		{"pre_verify", "completed", `{"decision":"block","reason":"more"}`, "block", 4},
		{"post_tool_call", "completed", `{"status":"error","error_message":"private tool error"}`, "ok", 0},
		{"pre_llm_call", "error", `{"context":"private context"}`, "error", 0},
		{"pre_tool_call", "cancelled", `null`, "cancelled", 0},
	} {
		t.Run(tc.event+"/"+tc.status, func(t *testing.T) {
			r, ok, err := (Decoder{}).Decode(completion(tc.event, tc.state, tc.result))
			if err != nil || !ok || r.Harness != "hermes" || r.ID != "hermes:delivery-1" || r.Status != tc.status || r.Chars != tc.chars {
				t.Fatalf("record=%+v %v %v", r, ok, err)
			}
			data, _ := json.Marshal(r)
			if strings.Contains(string(data), "private") || strings.Contains(string(data), "héllo") {
				t.Fatal("native text persisted")
			}
		})
	}
}

func TestHermesDoesNotInterpretRawShellDecisionAsPluginDirective(t *testing.T) {
	r, ok, err := (Decoder{}).Decode(completion("pre_tool_call", "completed", `{"decision":"block","reason":"private"}`))
	if err != nil || !ok || r.Status != "ok" || r.Chars != 0 {
		t.Fatalf("raw shell output must be normalized by Hermes first: %+v %v %v", r, ok, err)
	}
}
