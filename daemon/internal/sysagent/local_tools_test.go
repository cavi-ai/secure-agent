package sysagent

import (
	"os"
	"testing"
)

// Opt-in proof against the operator's local tool-capable model, using only
// synthetic text and a built-in procedure. No live findings are sent.
func TestLocalSystemAgentReadTools(t *testing.T) {
	endpoint, modelName := os.Getenv("SECURE_AGENT_TEST_SYSTEM_AGENT_ENDPOINT"), os.Getenv("SECURE_AGENT_TEST_SYSTEM_AGENT_MODEL")
	if endpoint == "" || modelName == "" {
		t.Skip("opt-in local model integration")
	}
	a, st := testAgent(t, endpoint, nil)
	cfg := a.config()
	cfg.Model = modelName
	a.SetConfig(cfg)
	if _, err := a.Send(ChatInput{Message: "Synthetic integration check: before answering call inspect_skill with id git. Then state which built-in procedure you read in one sentence. Do not propose a shell command."}); err != nil {
		t.Fatal(err)
	}
	a.Wait()
	rows := st.SysAgentMessages(10)
	last := rows[len(rows)-1]
	if last.Role != "assistant" || last.Content == "" || last.Usage == nil || last.Usage.ReadToolCalls < 1 || last.LocalCommand != nil {
		t.Fatal("local read-tool reply did not complete with an executed read call")
	}
	t.Logf("local read tool integration: calls=%d elapsed_ms=%d", last.Usage.ReadToolCalls, last.Usage.ElapsedMS)
}
