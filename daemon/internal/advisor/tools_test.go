package advisor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestDebugLogsContainMetadataAndExcludePromptAndReplyText(t *testing.T) {
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previous)
	previousDebug := debugAdvisorRequests
	debugAdvisorRequests = false
	defer func() { debugAdvisorRequests = previousDebug }()
	stub := &chatStub{content: "private-fixture-reply"}
	srv := newStubServer(t, stub)
	s := New(Config{Enabled: true, Endpoint: srv.URL, Debug: true}, &memSink{})
	for i := 0; i < 3; i++ {
		s.process(context.Background(), task{kind: "flag", flag: model.Flag{Rule: "private-fixture-rule", Evidence: []model.EvidenceItem{{Text: "private-fixture-evidence"}}}})
	}
	output := logs.String()
	if !strings.Contains(output, "advisor debug: request bytes=") || !strings.Contains(output, "completed=false") || strings.Contains(output, "private-fixture") {
		t.Fatalf("diagnostic log leaked content or omitted metadata: %s", output)
	}
	logs.Reset()
	s = New(Config{Enabled: true, Endpoint: srv.URL}, &memSink{})
	_, _ = s.chat(context.Background(), "private-fixture-system", "private-fixture-user", 100)
	if strings.Contains(logs.String(), "advisor debug:") {
		t.Fatal("debug metadata was logged while disabled")
	}
}

type scopedTestSink struct {
	memSink
	requested string
}

func (m *scopedTestSink) GetFlagResult(string) (model.Flag, bool, error) {
	return model.Flag{}, false, nil
}
func (m *scopedTestSink) SessionReport(id string) (store.SessionReport, bool) {
	m.requested = id
	return store.SessionReport{Session: model.Session{ID: id}, ToolCalls: 2,
		Tools:    []store.ReportCount{{Key: "Read", Count: 2}},
		Timeline: []store.ReportLine{{Label: "raw command must stay out"}}}, true
}

func TestSessionToolUsesOnlyFindingSessionAndOmitsRawDetail(t *testing.T) {
	sink := &scopedTestSink{}
	s := New(Config{Enabled: true, Endpoint: "http://127.0.0.1:1"}, sink)
	ctx := context.WithValue(context.Background(), reviewScopeKey{}, task{kind: "flag", flag: model.Flag{SessionID: "finding-session"}})
	result, err := s.runEvidenceTool(ctx, "inspect_session_activity", "fixture")
	if err != nil || sink.requested != "finding-session" || !strings.Contains(result, "Read") || strings.Contains(result, "raw command") {
		t.Fatalf("session tool escaped its scope or exposed detail: %s %v", result, err)
	}
}

func TestToolResultReuseIsConfinedToOneTask(t *testing.T) {
	classifierCalls := 0
	classifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		classifierCalls++
		w.Write([]byte(`{"answers":{"context":{"type":"choice","choice":"unknown","confidence":0.7,"probabilities":{"session":0.1,"operator_history":0.1,"sufficient":0.1,"unknown":0.7}}}}`))
	}))
	defer classifier.Close()
	modelCalls := 0
	modelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		modelCalls++
		if modelCalls%2 == 1 {
			w.Write([]byte(`{"choices":[{"message":{"tool_calls":[{"id":"a","type":"function","function":{"name":"classify_current_evidence","arguments":"{}"}},{"id":"b","type":"function","function":{"name":"classify_current_evidence","arguments":"{}"}}]}}]}`))
		} else {
			w.Write([]byte(`{"choices":[{"message":{"content":"answer"}}]}`))
		}
	}))
	defer modelServer.Close()
	s := New(Config{Enabled: true, Endpoint: modelServer.URL, ClassifierEndpoint: classifier.URL}, &memSink{})
	for i := 0; i < 2; i++ {
		ctx := context.WithValue(context.Background(), reviewScopeKey{}, task{kind: "flag"})
		if _, err := s.chat(ctx, "system", "fixture", 100); err != nil {
			t.Fatal(err)
		}
	}
	if classifierCalls != 2 {
		t.Fatalf("classifier calls=%d: expected one per fresh task", classifierCalls)
	}
}

func TestAdvisorFollowsScopedToolCall(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var req struct {
			Messages []struct {
				Role, Content string
				ToolCallID    string `json:"tool_call_id"`
			}
			Tools []json.RawMessage
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		if requests == 1 {
			if len(req.Tools) == 0 {
				t.Error("finding review offered no evidence tools")
			}
			w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call-1","type":"function","function":{"name":"inspect_current_evidence","arguments":"{}"}}]}}]}`))
			return
		}
		last := req.Messages[len(req.Messages)-1]
		if last.Role != "tool" || last.ToolCallID != "call-1" || !strings.Contains(last.Content, "fixture evidence") {
			t.Errorf("tool result not supplied: %+v", last)
		}
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"assessment\":\"suspicious\",\"confidence\":0.8,\"rationale\":\"Needs review\"}"}}]}`))
	}))
	defer srv.Close()
	sink := &memSink{rows: map[string]model.AdvisorVerdict{}}
	s := New(Config{Enabled: true, Endpoint: srv.URL, Model: "test", Timeout: time.Second}, sink)
	s.process(context.Background(), task{kind: "flag", subjectID: "f", flag: model.Flag{ID: "f", Rule: "test", Evidence: []model.EvidenceItem{{Kind: "text", Text: "fixture evidence"}}}})
	if requests != 2 || sink.rows["f"].Assessment != "suspicious" {
		t.Fatalf("tool review did not produce a verdict: calls=%d rows=%v", requests, sink.rows)
	}
}

func TestAdvisorReportsActiveTask(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		w.Write([]byte(`{"choices":[{"message":{"content":"{\"assessment\":\"suspicious\",\"confidence\":0.8,\"rationale\":\"Review\"}"}}]}`))
	}))
	defer srv.Close()
	s := New(Config{Enabled: true, Endpoint: srv.URL, Timeout: time.Second}, &memSink{rows: map[string]model.AdvisorVerdict{}})
	done := make(chan struct{})
	go func() {
		s.process(context.Background(), task{kind: "flag", subjectID: "f", flag: model.Flag{ID: "f"}})
		close(done)
	}()
	<-started
	body, _ := json.Marshal(s.Health())
	var health map[string]any
	json.Unmarshal(body, &health)
	close(release)
	<-done
	if health["state"] != "answering" || health["active_kind"] != "flag" {
		t.Fatalf("active review invisible: %s", body)
	}
}

func TestAdvisorRejectsToolsOutsideSubjectScope(t *testing.T) {
	for _, tc := range []struct{ name, args string }{{"run_shell", `{}`}, {"inspect_current_evidence", `{"path":"/unrelated/secret"}`}, {"inspect_current_evidence", `null`}} {
		t.Run(tc.name+tc.args, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"id": "c", "type": "function", "function": map[string]any{"name": tc.name, "arguments": tc.args}}}}}}})
			}))
			defer srv.Close()
			sink := &memSink{rows: map[string]model.AdvisorVerdict{}}
			s := New(Config{Enabled: true, Endpoint: srv.URL, Timeout: time.Second}, sink)
			s.process(context.Background(), task{kind: "flag", subjectID: "f", flag: model.Flag{ID: "f"}})
			if calls != 1 || len(sink.rows) != 0 || s.Health().LastError == "" {
				t.Fatalf("unscoped tool was accepted: calls=%d rows=%v", calls, sink.rows)
			}
		})
	}
}

func TestAdvisorStopsRepeatedToolRequests(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"id": fmt.Sprintf("c%d", calls), "type": "function", "function": map[string]any{"name": "inspect_current_evidence", "arguments": "{}"}}}}}}})
	}))
	defer srv.Close()
	sink := &memSink{rows: map[string]model.AdvisorVerdict{}}
	s := New(Config{Enabled: true, Endpoint: srv.URL, Timeout: time.Second}, sink)
	s.process(context.Background(), task{kind: "flag", subjectID: "f", flag: model.Flag{ID: "f"}})
	if calls != 4 || len(sink.rows) != 0 || !strings.Contains(s.Health().LastError, "budget exhausted") {
		t.Fatalf("tool loop not bounded: calls=%d health=%+v", calls, s.Health())
	}
}

func TestAdvisorRejectsOversizedContextBeforeHTTP(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer srv.Close()
	s := New(Config{Enabled: true, Endpoint: srv.URL, Timeout: time.Second}, &memSink{rows: map[string]model.AdvisorVerdict{}})
	_, err := s.chat(context.Background(), "system", strings.Repeat("large evidence ", 4000), 100)
	if err == nil || calls != 0 {
		t.Fatalf("oversized context sent: calls=%d err=%v", calls, err)
	}
}

func TestAdvisorMasksEvidenceAndRefusesUnmaskableContext(t *testing.T) {
	stub := &chatStub{content: `{"assessment":"suspicious","confidence":0.7,"rationale":"Review"}`}
	srv := newStubServer(t, stub)
	s := New(Config{Enabled: true, Endpoint: srv.URL, Timeout: time.Second, Mask: func(v string) (string, bool) {
		return strings.ReplaceAll(v, "secret-fixture", "[REDACTED]"), !strings.Contains(v, "unmaskable-fixture")
	}}, &memSink{rows: map[string]model.AdvisorVerdict{}})
	if _, err := s.chat(context.Background(), "system", "secret-fixture", 100); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stub.lastBody, "secret-fixture") || !strings.Contains(stub.lastBody, "[REDACTED]") {
		t.Fatal("evidence crossed the model boundary unmasked")
	}
	if _, err := s.chat(context.Background(), "system", "unmaskable-fixture", 100); err == nil || stub.requests != 1 {
		t.Fatal("unmaskable evidence reached the model")
	}
}
