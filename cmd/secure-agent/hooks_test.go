package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
)

const forwardedHook = `{"id":"delivery-1","notification":{"method":"hook/completed","params":{"threadId":"session-1","run":{"id":"stop:0:/home/example/hooks.json","eventName":"stop","status":"blocked","completedAt":1791882001,"durationMs":7,"entries":[{"kind":"feedback","text":"retry carefully"}]}}}}`

func TestCodexRecorderMixedHostHealthAndCompletions(t *testing.T) {
	report := `{"type":"hook_forwarder","version":1,"harness":"codex","forwarder_id":"instance-1","sequence":1,"ts":"2026-10-13T10:00:00Z","state":"connected","pending":0,"delivery_failures":0,"dropped":0}`
	p := filepath.Join(t.TempDir(), "activity.jsonl")
	if err := runHooks(strings.NewReader(report+"\n"+forwardedHook+"\n"), []string{"record", "--format", "codex", "--output", p}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("records=%d", len(lines))
	}
	if _, ok, err := hookrun.DecodeForwarderReport(lines[0]); !ok || err != nil {
		t.Fatalf("report missing: %v", err)
	}
	if _, ok, err := hookrun.DecodeRecord(lines[1]); !ok || err != nil {
		t.Fatalf("completion missing: %v", err)
	}
	for _, bad := range []string{strings.Replace(report, `"codex"`, `"hermes"`, 1), strings.Replace(report, `"pending":0`, `"pending":null`, 1)} {
		if err := runHooks(strings.NewReader(bad+"\n"), []string{"record", "--format", "codex", "--output", p}); err == nil {
			t.Fatal("invalid or mismatched report accepted")
		}
	}
}

func TestHooksRecorderWritesOnlyCompletionMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "activity.jsonl")
	input := `{"method":"hook/started","params":{}}` + "\n" + forwardedHook + "\n"
	if err := runHooks(strings.NewReader(input), []string{"record", "--format", "codex", "--output", path}); err != nil {
		t.Fatal(err)
	}
	if err := runHooks(strings.NewReader(forwardedHook+"\n"), []string{"record", "--format", "codex", "--output", path}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("wrote %d records", len(lines))
	}
	for _, line := range lines {
		var r hookrun.Record
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatal(err)
		}
		if r.ID != "codex:delivery-1" || r.Status != "block" || r.Chars != 15 || r.DurationMs != 7 {
			t.Fatalf("record = %+v", r)
		}
		if r.Evidence == nil || r.Evidence.HandlerID == "" {
			t.Fatal("recorder lost native handler identity")
		}
		if bytes.Contains(line, []byte("/home/")) || bytes.Contains(line, []byte("retry carefully")) {
			t.Fatal("private input persisted")
		}
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("record file permissions: %v %v", info, err)
	}
}

func TestHooksRecorderRejectsInvalidInputWithoutLeakingIt(t *testing.T) {
	for _, input := range []string{
		strings.Replace(forwardedHook, `"delivery-1"`, `"/home/private"`, 1),
		`{"id":"private`,
		strings.Repeat("private", 200000),
	} {
		path := filepath.Join(t.TempDir(), "activity.jsonl")
		err := runHooks(strings.NewReader(input+"\n"), []string{"record", "--format", "codex", "--output", path})
		if err == nil || strings.Contains(err.Error(), "private") {
			t.Fatalf("error = %v", err)
		}
		if data, _ := os.ReadFile(path); len(data) != 0 {
			t.Fatal("invalid input written")
		}
	}
}

func TestHooksRecorderAcceptsCommonContract(t *testing.T) {
	path := filepath.Join(t.TempDir(), "activity.jsonl")
	input := `{"type":"hook_run","version":1,"harness":"hermes","session_id":"session-1","run_id":"hermes:delivery-1","ts":"2026-10-13T10:00:00Z","event":"pre_tool_call","script":"guard.py","status":"deny","duration_ms":4,"chars":2}`
	if err := runHooks(strings.NewReader(input+"\n"), []string{"record", "--format", "record", "--output", path}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !bytes.Contains(data, []byte(`"harness":"hermes"`)) {
		t.Fatal("common record missing")
	}
}

func TestCommonRecorderRejectsMalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "activity.jsonl")
	err := runHooks(strings.NewReader(`{"private`+"\n"), []string{"record", "--format", "record", "--output", path})
	if err == nil || strings.Contains(err.Error(), "private") {
		t.Fatalf("error = %v", err)
	}
	if data, _ := os.ReadFile(path); len(data) != 0 {
		t.Fatal("malformed input written")
	}
}

func TestRecorderNativeAdapters(t *testing.T) {
	for _, tc := range []struct {
		harness, event, result, extra, status string
		chars                                 int64
	}{
		{"openclaw", "before_tool_call", `{"block":true,"blockReason":"no"}`, "", "block", 2},
		{"hermes", "pre_llm_call", `{"context":"héllo"}`, "", "inject", 5},
		{"opencode", "permission.evaluate", `{"effect":"deny","message":"no"}`, `,"protocol":"opencode-v2","before":{"effect":"allow"}`, "deny", 2},
	} {
		t.Run(tc.harness, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "activity.jsonl")
			input := `{"type":"hook_completed","version":1,"harness":"` + tc.harness + `","id":"delivery-1","session_id":"session-1","ts":"2026-10-13T10:00:00Z","event":"` + tc.event + `","state":"completed","duration_ms":9,"result":` + tc.result + tc.extra + `}`
			if err := runHooks(strings.NewReader(input+"\n"), []string{"record", "--format", tc.harness, "--output", path}); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			r, ok, err := hookrun.DecodeRecord(bytes.TrimSpace(data))
			if err != nil || !ok || r.Status != tc.status || r.Chars != tc.chars || r.Harness != tc.harness {
				t.Fatalf("record=%+v %v %v", r, ok, err)
			}
		})
	}
}
