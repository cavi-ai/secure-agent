package sysagent

import (
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestChatBoundsWholeContextAndKeepsLatestQuestion(t *testing.T) {
	ol := newFakeOllama(t, "0.15.1", "qwen3:latest")
	ol.setReply("Review the latest task")
	a, st := testAgent(t, ol.URL, nil)
	for i := 0; i < 20; i++ {
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		st.PutSysAgentMessage(model.SysAgentMessage{TS: time.Now(), Role: role, Content: strings.Repeat("old context ", 650)})
	}
	if _, err := a.Send(ChatInput{Message: "the latest question"}); err != nil {
		t.Fatal(err)
	}
	a.Wait()
	if len(ol.requests) != 1 {
		t.Fatalf("expected a bounded chat request, got %d", len(ol.requests))
	}
	msgs := ol.requests[0]["messages"].([]any)
	size := 0
	for _, m := range msgs {
		size += len(m.(map[string]any)["content"].(string))
	}
	if size > 32768 {
		t.Fatalf("chat context grew to %d bytes", size)
	}
	if msgs[len(msgs)-1].(map[string]any)["content"] != "the latest question" {
		t.Fatal("latest question lost")
	}
	if !strings.Contains(msgs[0].(map[string]any)["content"].(string), "Older conversation") {
		t.Fatal("context omission not disclosed to model")
	}
	if msgs[1].(map[string]any)["role"] != "user" {
		t.Fatal("context begins with an orphaned assistant turn")
	}
}
