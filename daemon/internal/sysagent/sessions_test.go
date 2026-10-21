package sysagent

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestEnablingPersistentAgentRecoversInterruptedWork(t *testing.T) {
	st, err := store.Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.PutSysAgentRun(model.SysAgentRun{TS: time.Now(), Status: "running"})
	st.PutSysAgentPlan(model.SysAgentPlan{Status: "running"})
	a := NewPersistent(st, t.TempDir(), nil)
	a.historyKey = func(string) ([]byte, error) { return bytes.Repeat([]byte{9}, 32), nil }
	a.SetConfig(config.SystemAgentConfig{})
	a.Recover() // Startup while encrypted history is locked.
	a.SetConfig(config.SystemAgentConfig{Enabled: true})
	if runs := st.SysAgentRuns(10); len(runs) != 1 || runs[0].Status != "failed" {
		t.Fatalf("interrupted run was not recovered after enable: %+v", runs)
	}
	if plans := st.SysAgentPlans(10); len(plans) != 1 || plans[0].Status != "failed" {
		t.Fatalf("interrupted plan was not recovered after enable: %+v", plans)
	}
}

func TestFreshSessionRetainsScopedFactsWithoutCommands(t *testing.T) {
	ol := newFakeOllama(t, "0.15.0", "qwen3")
	ol.setReply("Answer")
	a, _ := testAgent(t, ol.URL, nil)
	if _, err := a.Send(ChatInput{Message: "hello", Workdir: "/project/one"}); err != nil {
		t.Fatal(err)
	}
	a.Wait()
	if err := a.Remember("/project/one", "worktree-check", "Checked branch status; no local changes observed", []string{"worktree:fixture"}); err != nil {
		t.Fatal(err)
	}
	before := a.Session().ID
	if err := a.Clear(); err != nil {
		t.Fatal(err)
	}
	if len(a.Messages(20)) != 0 {
		t.Fatal("new chat retained old conversation")
	}
	if len(a.Memory("/project/one")) != 1 || len(a.Memory("/project/two")) != 0 {
		t.Fatal("memory leaked across project scopes or was lost")
	}
	if _, err := a.Send(ChatInput{Message: "continue", Workdir: "/project/one"}); err != nil {
		t.Fatal(err)
	}
	a.Wait()
	if a.Session().ID == before {
		t.Fatal("new chat reused session")
	}
	if !strings.Contains(ol.requests[len(ol.requests)-1]["messages"].([]any)[0].(map[string]any)["content"].(string), "Checked branch status") {
		t.Fatal("new session did not retrieve retained facts")
	}
}

func TestIdleSessionRotatesAndDoesNotRememberChatNoise(t *testing.T) {
	ol := newFakeOllama(t, "0.15.0", "qwen3")
	ol.setReply("Answer")
	a, _ := testAgent(t, ol.URL, nil)
	now := time.Now()
	a.now = func() time.Time { return now }
	a.Send(ChatInput{Message: "hello"})
	a.Wait()
	before := a.Session().ID
	now = now.Add(31 * time.Minute)
	a.Send(ChatInput{Message: "hello again"})
	a.Wait()
	if a.Session().ID == before || len(a.Memory(a.home)) != 0 {
		t.Fatal("idle session did not rotate or ordinary chatter became memory")
	}
}

func TestCapturedFindingRetainsOnlyScopedDetectorMetadata(t *testing.T) {
	a, st := testAgent(t, "http://localhost", nil)
	_, err := st.PutFlag(model.Flag{ID: "retained-finding", Workspace: "/project/one", Rule: "credential-read", Severity: 3,
		TS: time.Now(), Evidence: model.EvidenceFromStrings("raw-evidence-sentinel")})
	if err != nil {
		t.Fatal(err)
	}
	a.captureScope(model.SysAgentMessage{FlagIDs: []string{"retained-finding"}})
	facts := a.Memory("/project/one")
	if len(facts) != 1 || !strings.Contains(facts[0].Summary, "credential-read") || strings.Contains(facts[0].Summary, "raw-evidence-sentinel") || facts[0].References[0] != "flag:retained-finding" {
		t.Fatalf("expected a detector reference without raw evidence: %+v", facts)
	}
	if len(a.Memory("/project/two")) != 0 {
		t.Fatal("detector memory crossed project scopes")
	}
}
