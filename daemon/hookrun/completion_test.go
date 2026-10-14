package hookrun

import (
	"strings"
	"testing"
)

func TestCompletionEnvelopeRejectsInvalidMetadata(t *testing.T) {
	base := `{"type":"hook_completed","version":1,"harness":"openclaw","id":"delivery-1","session_id":"session-1","ts":"2026-10-13T10:00:00Z","event":"before_tool_call","state":"completed","duration_ms":9,"result":{"private":"private output"}}`
	for _, replacement := range [][2]string{
		{`"version":1`, `"version":2`}, {`"id":"delivery-1"`, `"id":"/home/private"`},
		{`"session_id":"session-1"`, `"session_id":""`}, {`"state":"completed"`, `"state":"running"`},
		{`"duration_ms":9`, `"duration_ms":-1`}, {`"ts":"2026-10-13T10:00:00Z"`, `"ts":"invalid"`},
		{`"event":"before_tool_call"`, `"event":"/home/private"`}, {`"event":"before_tool_call"`, `"event":"before_tool_call","output":"private"`},
	} {
		line := strings.Replace(base, replacement[0], replacement[1], 1)
		if _, _, ok, err := DecodeCompletion([]byte(line), "openclaw"); !ok || err == nil || strings.Contains(err.Error(), "private") {
			t.Fatalf("invalid metadata: ok=%v err=%v", ok, err)
		}
	}
	if _, _, ok, err := DecodeCompletion([]byte(base), "hermes"); !ok || err == nil {
		t.Fatal("wrong adapter accepted completion")
	}
	_, r, ok, err := DecodeCompletion([]byte(base), "openclaw")
	if err != nil || !ok || r.ID != "openclaw:delivery-1" || r.Chars != 0 {
		t.Fatalf("metadata=%+v %v %v", r, ok, err)
	}
}
