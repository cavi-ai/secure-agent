package codex

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Fixtures follow Codex app-server v2's camelCase HookCompletedNotification.
// The native id identifies a handler, not an execution; the host's envelope
// id must survive retries and differ between distinct completions.
func codexCompletion(id, status string) []byte {
	return []byte(`{"id":"` + id + `","notification":{"method":"hook/completed","params":{"threadId":"thread-1","turnId":"turn-1","run":{"id":"pre-tool-use:0:/home/example/.codex/hooks.json","eventName":"preToolUse","handlerType":"command","status":"` + status + `","startedAt":1791882000,"completedAt":1791882001,"durationMs":12,"sourcePath":"/home/example/.codex/hooks.json","statusMessage":"private status","entries":[{"kind":"context","text":"héllo 🌍"},{"kind":"warning","text":"private warning"},{"kind":"error","text":"private error"}]}}}}`)
}

func TestCodexDecoderNormalizesMetadata(t *testing.T) {
	for _, tc := range []struct{ native, want string }{
		{"completed", "inject"}, {"failed", "error"}, {"blocked", "block"}, {"stopped", "block"},
	} {
		t.Run(tc.native, func(t *testing.T) {
			r, ok, err := (Decoder{}).Decode(codexCompletion("delivery-1", tc.native))
			if err != nil || !ok {
				t.Fatalf("decoded=%v error=%v", ok, err)
			}
			if r.ID != "codex:delivery-1" || r.SessionID != "thread-1" || r.Harness != "codex" || r.Event != "PreToolUse" || r.Status != tc.want || r.Chars != 7 || r.DurationMs != 12 || r.Script != "" || !r.TS.Equal(time.Unix(1791882001, 0)) {
				t.Fatalf("record = %+v", r)
			}
			data, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			for _, private := range []string{"/home/", "private", "héllo", "sourcePath", "turn-1"} {
				if strings.Contains(string(data), private) {
					t.Fatalf("record retained %q", private)
				}
			}
		})
	}
}

func TestCodexDeliveryIdentity(t *testing.T) {
	a, _, _ := (Decoder{}).Decode(codexCompletion("delivery-1", "completed"))
	b, _, _ := (Decoder{}).Decode(codexCompletion("delivery-2", "completed"))
	retry, _, _ := (Decoder{}).Decode(codexCompletion("delivery-1", "completed"))
	if a.ID == b.ID || !reflect.DeepEqual(a, retry) {
		t.Fatal("distinct runs collapsed or retry changed")
	}
}

func TestCodexNativeHandlerIdentity(t *testing.T) {
	a, _, err := (Decoder{}).Decode(codexCompletion("first", "failed"))
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := (Decoder{}).Decode(codexCompletion("second", "failed"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Evidence.HandlerID == "" || a.Evidence.HandlerID != b.Evidence.HandlerID || a.ID == b.ID {
		t.Fatalf("handler and execution identities mixed: %+v %+v", a, b)
	}
	if !strings.HasPrefix(a.Evidence.HandlerID, "codex-handler:") || len(a.Evidence.HandlerID) != 78 {
		t.Fatalf("unexpected handler identity: %q", a.Evidence.HandlerID)
	}
	if a.Evidence.HandlerID != "codex-handler:7cd6c94d75aeffff78642e6e1cc48f1df25f995ae96d71f2bdffd5e00a6a0652" {
		t.Fatal("native handler identity format changed")
	}
	for _, replacement := range []string{"pre-tool-use:1:/home/example/.codex/hooks.json", "pre-tool-use:0:/home/other/.codex/hooks.json"} {
		line := strings.Replace(string(codexCompletion("second", "failed")), "pre-tool-use:0:/home/example/.codex/hooks.json", replacement, 1)
		r, _, err := (Decoder{}).Decode([]byte(line))
		if err != nil {
			t.Fatal(err)
		}
		if r.Evidence.HandlerID == a.Evidence.HandlerID {
			t.Fatal("different configured handlers collapsed")
		}
	}
	data, _ := json.Marshal(a)
	for _, raw := range []string{"/home/", "hooks.json", "pre-tool-use:0:"} {
		if strings.Contains(string(data), raw) {
			t.Fatalf("raw native identity retained: %q", raw)
		}
	}
	if a.Evidence.ConfigID != "" || a.Evidence.OperationID != "" || a.Script != "" {
		t.Fatalf("handler identity invented other metadata: %+v", a)
	}
}

func TestCodexHandlerIdentityMissingAndOverride(t *testing.T) {
	base := string(codexCompletion("r", "failed"))
	for _, native := range []string{`""`, `null`} {
		line := strings.Replace(base, `"pre-tool-use:0:/home/example/.codex/hooks.json"`, native, 1)
		r, _, err := (Decoder{}).Decode([]byte(line))
		if err != nil || r.Evidence.HandlerID != "" {
			t.Fatalf("missing identity inferred: %+v %v", r, err)
		}
	}
	line := strings.Replace(base, `"notification":`, `"evidence":{"handler_id":"host-handler","config_id":"revision"},"notification":`, 1)
	r, _, err := (Decoder{}).Decode([]byte(line))
	if err != nil || r.Evidence.HandlerID != "host-handler" || r.Evidence.ConfigID != "revision" {
		t.Fatalf("host identity lost: %+v %v", r, err)
	}
}

func TestCodexEvidenceAndContextSemantics(t *testing.T) {
	line := strings.Replace(string(codexCompletion("r", "completed")), `"notification":`, `"evidence":{"handler_id":"h","config_id":"c","operation_id":"o","execution_mode":"foreground"},"notification":`, 1)
	r, _, err := (Decoder{}).Decode([]byte(line))
	if err != nil || r.Evidence == nil || r.Evidence.HandlerID != "h" || r.Evidence.ContextChars == nil || *r.Evidence.ContextChars != 7 || !r.Evidence.DurationKnown {
		t.Fatalf("evidence = %+v %v", r, err)
	}
	line = strings.Replace(line, `"durationMs":12`, `"durationMs":null`, 1)
	line = strings.Replace(line, `"kind":"context"`, `"kind":"feedback"`, 1)
	r, _, err = (Decoder{}).Decode([]byte(line))
	if err != nil || r.Evidence.DurationKnown || *r.Evidence.ContextChars != 0 || r.Chars != 7 {
		t.Fatalf("guessed measurement = %+v %v", r, err)
	}
}

func TestCodexMissingEntriesAreUnknown(t *testing.T) {
	line := `{"id":"r","notification":{"method":"hook/completed","params":{"threadId":"t","run":{"eventName":"preToolUse","status":"completed","completedAt":1791882001}}}}`
	r, _, err := (Decoder{}).Decode([]byte(line))
	if err != nil || r.Evidence == nil || r.Evidence.CharsKnown || r.Evidence.ContextChars != nil {
		t.Fatalf("missing entries became measured zero: %+v %v", r, err)
	}
}

func TestCodexDecoderUsesOnlyExplicitSafeScriptLabel(t *testing.T) {
	input := strings.Replace(string(codexCompletion("delivery-1", "completed")), `"notification":`, `"script":"guard.py","notification":`, 1)
	r, ok, err := (Decoder{}).Decode([]byte(input))
	if err != nil || !ok || r.Script != "guard.py" {
		t.Fatalf("script label = %q, %v, %v", r.Script, ok, err)
	}
	input = strings.Replace(input, `"script":"guard.py"`, `"script":"/home/private/guard.py"`, 1)
	if _, _, err := (Decoder{}).Decode([]byte(input)); err == nil {
		t.Fatal("script path accepted")
	}
}

func TestCodexDecoderSkipsOtherNotificationsAndRejectsBadCompletions(t *testing.T) {
	for _, line := range []string{`{"method":"hook/started","params":{}}`, `{"method":"turn/completed"}`, `{"id":1,"result":{}}`} {
		if _, ok, err := (Decoder{}).Decode([]byte(line)); ok || err != nil {
			t.Fatalf("unrelated notification: ok=%v err=%v", ok, err)
		}
	}
	for _, line := range []string{
		strings.Replace(string(codexCompletion("delivery-1", "completed")), `"id":"delivery-1",`, "", 1),
		string(codexCompletion("delivery-1", "future_status")),
		strings.Replace(string(codexCompletion("delivery-1", "completed")), `"thread-1"`, `""`, 1),
		strings.Replace(string(codexCompletion("delivery-1", "completed")), `"durationMs":12`, `"durationMs":-1`, 1),
		strings.Replace(string(codexCompletion("delivery-1", "completed")), `"completedAt":1791882001`, `"completedAt":null`, 1),
		string(codexCompletion("/home/private", "completed")),
		`{"id":"x","notification":{"method":"hook/completed","params":{}}}`,
	} {
		if _, _, err := (Decoder{}).Decode([]byte(line)); err == nil {
			t.Fatal("bad completion accepted")
		}
	}
}
