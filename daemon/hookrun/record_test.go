package hookrun

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRecordContractRejectsInvalidMetadata(t *testing.T) {
	r, _, err := (CodexDecoder{}).Decode(codexCompletion("delivery-1", "completed"))
	if err != nil {
		t.Fatal(err)
	}
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
