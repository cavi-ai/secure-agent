package sysagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

type unavailableEvidenceStore struct{ Store }

func (unavailableEvidenceStore) QueryFlagsResult(store.FlagFilter) ([]model.Flag, error) {
	return nil, fmt.Errorf("private store failure")
}
func (unavailableEvidenceStore) GetFlagResult(string) (model.Flag, bool, error) {
	return model.Flag{}, false, fmt.Errorf("private store failure")
}
func (unavailableEvidenceStore) SessionReportResult(string) (store.SessionReport, bool, error) {
	return store.SessionReport{}, false, fmt.Errorf("private store failure")
}

func TestSnapshotFailureAndCacheLimits(t *testing.T) {
	a, st := testAgent(t, "http://localhost", nil)
	a.st = unavailableEvidenceStore{Store: st}
	scope := a.captureScope(model.SysAgentMessage{})
	if strings.Contains(scope.snapshot, "private") || !strings.Contains(scope.snapshot, `"available":false`) || len(scope.findings) != 0 {
		t.Fatal("unavailable snapshot presented as empty evidence")
	}
	a.st = st
	_, err := st.PutFlag(model.Flag{ID: "oversized", Evidence: []model.EvidenceItem{{Kind: "text", Label: strings.Repeat("x", maxChatToolBytes)}}})
	if err != nil {
		t.Fatal(err)
	}
	scope = a.captureScope(model.SysAgentMessage{FlagIDs: []string{"oversized"}})
	if !scope.oversized["oversized"] || len(scope.findings["oversized"].Evidence) != 0 {
		t.Fatal("oversized finding retained in reply cache")
	}
	result, err := a.readTool(context.Background(), scope, "inspect_finding", `{"id":"oversized"}`)
	if err != nil || !strings.Contains(result, `"available":false`) {
		t.Fatal("oversized finding presented as empty evidence")
	}
}

func TestExplicitNonToolModelsRetainOrdinaryChat(t *testing.T) {
	info := ollamaInfo{Capabilities: map[string][]string{"plain:latest": {"completion"}, "tools:latest": {"completion", "tools"}}}
	if info.supportsTools("plain") || !info.supportsTools("tools") || !info.supportsTools("legacy") {
		t.Fatal("incorrect capability selection")
	}
}

func TestEvidenceToolsAreScopedAndMasked(t *testing.T) {
	a, _ := testAgent(t, "http://localhost", nil)
	scope := replyScope{findings: map[string]model.Flag{"f1": {ID: "f1", SessionID: "s1", Evidence: []model.EvidenceItem{{Kind: "text", Label: "ghp_TESTTOKEN"}}}}}
	result, err := a.readTool(context.Background(), scope, "inspect_finding", `{"id":"f1"}`)
	if err != nil || strings.Contains(result, "ghp_TESTTOKEN") || !strings.Contains(result, "REDACTED") || !json.Valid([]byte(result)) {
		t.Fatalf("masked valid evidence required: %s %v", result, err)
	}
	for _, input := range []struct{ name, args string }{
		{"inspect_finding", `{"id":"other"}`}, {"inspect_session_activity", `{"id":"other"}`},
		{"inspect_skill", `{"id":"../../secret"}`}, {"inspect_snapshot", `{"path":"/etc/passwd"}`},
		{"inspect_snapshot", `{} {}`}, {"run_command", `{}`},
		{"inspect_snapshot", `{"id":""}`}, {"inspect_snapshot", `null`},
	} {
		if _, err := a.readTool(context.Background(), scope, input.name, input.args); err == nil {
			t.Fatalf("out-of-scope tool accepted: %+v", input)
		}
	}
	scope.findings["f1"] = model.Flag{ID: "f1", Evidence: []model.EvidenceItem{{Kind: "text", Label: "ENCODED-SECRET"}}}
	if _, err := a.readTool(context.Background(), scope, "inspect_finding", `{"id":"f1"}`); err == nil {
		t.Fatal("unmaskable evidence crossed boundary")
	}
}

func TestFreshChatReseedsWithoutOldConversation(t *testing.T) {
	ol := newFakeOllama(t, "0.15.1", "test:latest")
	ol.setReply("Answer")
	a, _ := testAgent(t, ol.URL, nil)
	if _, err := a.Send(ChatInput{Message: "old conversation"}); err != nil {
		t.Fatal(err)
	}
	a.Wait()
	if err := a.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Send(ChatInput{Message: "SSH setup"}); err != nil {
		t.Fatal(err)
	}
	a.Wait()
	data, _ := json.Marshal(ol.requests[1])
	system := ol.requests[1]["messages"].([]any)[0].(map[string]any)["content"].(string)
	if strings.Contains(string(data), "old conversation") || !strings.Contains(system, "Captured findings index") || !strings.Contains(string(data), "inspect_skill") || !strings.Contains(system, `<skill id="ssh">`) {
		t.Fatalf("fresh context not seeded: %s", data)
	}
	if a.Work().State != "idle" || a.Work().ActiveTool != "" {
		t.Fatalf("stale activity: %+v", a.Work())
	}
}

func TestDebugLogsAreMetadataOnly(t *testing.T) {
	a, _ := testAgent(t, "http://localhost", nil)
	var logs bytes.Buffer
	original := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(original)
	cfg := a.config()
	cfg.Debug = true
	a.SetConfig(cfg)
	a.client = &http.Client{Transport: chatRoundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"choices":[{"message":{"content":"private reply marker"}}]}`))}, nil
	})}
	_, _, err := a.chatWithTools(context.Background(), "http://localhost", "test", []chatMessage{{Role: "user", Content: "private evidence marker"}}, replyScope{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "request round=1 bytes=") || strings.Contains(logs.String(), "private") {
		t.Fatalf("unsafe diagnostics: %s", logs.String())
	}
}

func TestResponseAndRequestBounds(t *testing.T) {
	a, _ := testAgent(t, "http://localhost", nil)
	requests := 0
	a.client = &http.Client{Transport: chatRoundTrip(func(r *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxChatResponseBytes+1)))}, nil
	})}
	if _, _, err := a.chatWithTools(context.Background(), "http://localhost", "test", []chatMessage{{Role: "user", Content: "Hi"}}, replyScope{}); err == nil {
		t.Fatal("oversized response accepted")
	}
	requests = 0
	if _, _, err := a.chatWithTools(context.Background(), "http://localhost", "test", []chatMessage{{Role: "user", Content: strings.Repeat("x", chatContextBytes)}}, replyScope{}); err == nil || requests != 0 {
		t.Fatal("oversized request crossed HTTP boundary")
	}
}

func TestToolExchangeIsBoundedAndTaskLocal(t *testing.T) {
	a, _ := testAgent(t, "http://localhost", nil)
	requests := 0
	a.client = &http.Client{Transport: chatRoundTrip(func(r *http.Request) (*http.Response, error) {
		requests++
		body, _ := io.ReadAll(r.Body)
		if len(body) > chatContextBytes {
			t.Fatalf("request exceeds context budget: %d", len(body))
		}
		if requests%2 == 0 && !strings.Contains(string(body), `"tool_call_id":"call"`) {
			t.Fatal("missing matching tool result")
		}
		answer := `{"choices":[{"message":{"content":"","tool_calls":[{"id":"call","type":"function","function":{"name":"inspect_skill","arguments":"{\"id\":\"ssh\"}"}}]}}],"usage":{"prompt_tokens":10}}`
		if requests%2 == 0 {
			answer = `{"choices":[{"message":{"content":"Answer"}}],"usage":{"prompt_tokens":20,"completion_tokens":5}}`
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(answer))}, nil
	})}
	for range 2 {
		text, usage, err := a.chatWithTools(context.Background(), "http://localhost", "test", []chatMessage{{Role: "system", Content: "Procedures"}, {Role: "user", Content: "SSH"}}, replyScope{})
		if err != nil || text != "Answer" || usage.ToolCalls != 1 || usage.PromptTokens != 30 {
			t.Fatalf("text=%q usage=%+v err=%v", text, usage, err)
		}
	}
	if requests != 4 {
		t.Fatalf("task result retained between replies: %d", requests)
	}
	requests = 0
	a.client.Transport = chatRoundTrip(func(r *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"choices":[{"message":{"tool_calls":[{"id":"same","type":"function","function":{"name":"inspect_snapshot","arguments":"{}"}}]}}]}`))}, nil
	})
	if _, _, err := a.chatWithTools(context.Background(), "http://localhost", "test", []chatMessage{{Role: "user", Content: "Hi"}}, replyScope{}); err == nil || requests > maxChatRounds {
		t.Fatalf("unbounded tool loop: calls=%d err=%v", requests, err)
	}
}
