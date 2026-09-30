package sysagent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

type unavailableRunStore struct{ Store }

func (s unavailableRunStore) PutSysAgentRun(model.SysAgentRun) int64 { return 0 }

type unavailableMessageStore struct{ Store }

func (s unavailableMessageStore) PutSysAgentMessage(model.SysAgentMessage) int64 { return 0 }

type unavailablePlanUpdateStore struct{ Store }

func (s unavailablePlanUpdateStore) PutSysAgentPlan(p model.SysAgentPlan) int64 {
	if p.ID != 0 {
		return 0
	}
	return s.Store.PutSysAgentPlan(p)
}

func TestDispatchClosesRunWhenPlanUpdateFails(t *testing.T) {
	for _, mode := range []string{ModeHeadless, ModeTerminal} {
		t.Run(mode, func(t *testing.T) {
			ol := newFakeOllama(t, "0.15.1", "qwen3")
			dir := t.TempDir()
			marker := filepath.Join(dir, "executed")
			bin := fakeBin(t, dir, "codex", "touch "+shellQuote(marker)+"\n")
			a, st := testAgent(t, ol.URL, map[string]string{"codex": bin})
			a.openTerminal = func(string) error { return os.WriteFile(marker, []byte("opened"), 0600) }
			p, err := a.SavePlan(PlanInput{Harness: "codex", Mode: mode, Workdir: dir, Task: "check"})
			if err != nil {
				t.Fatal(err)
			}
			a.st = unavailablePlanUpdateStore{st}
			_, err = a.Dispatch(context.Background(), DispatchInput{PlanID: p.ID})
			a.Wait()
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("dispatch error = %v", err)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("execution began without durable plan update")
			}
			runs := st.SysAgentRuns(1)
			if len(runs) != 1 || runs[0].Status != "failed" || runs[0].FinishedAt == nil {
				t.Fatalf("unstarted run was not closed: %+v", runs)
			}
		})
	}
}

func TestDispatchRefusesUnrecordedExecution(t *testing.T) {
	for _, mode := range []string{ModeHeadless, ModeTerminal} {
		t.Run(mode, func(t *testing.T) {
			ol := newFakeOllama(t, "0.15.1", "qwen3")
			dir := t.TempDir()
			marker := filepath.Join(dir, "executed")
			bin := fakeBin(t, dir, "codex", "touch "+shellQuote(marker)+"\n")
			a, st := testAgent(t, ol.URL, map[string]string{"codex": bin})
			a.openTerminal = func(string) error { return os.WriteFile(marker, []byte("opened"), 0600) }
			p, err := a.SavePlan(PlanInput{Harness: "codex", Mode: mode, Workdir: dir, Task: "check"})
			if err != nil {
				t.Fatal(err)
			}
			a.st = unavailableRunStore{st}
			_, err = a.Dispatch(context.Background(), DispatchInput{PlanID: p.ID})
			a.Wait()
			if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
				t.Error("execution began without a durable run record")
			}
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("dispatch error = %v", err)
			}
		})
	}
}

func TestSendRefusesUnstoredMessage(t *testing.T) {
	ol := newFakeOllama(t, "0.15.1", "qwen3")
	a, st := testAgent(t, ol.URL, nil)
	a.st = unavailableMessageStore{st}
	_, err := a.Send(ChatInput{Message: "hello"})
	a.Wait()
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("send error = %v", err)
	}
	ol.mu.Lock()
	defer ol.mu.Unlock()
	if len(ol.requests) != 0 {
		t.Fatal("unrecorded message reached model")
	}
	if a.Chatting() {
		t.Fatal("failed send left chat busy")
	}
}

func TestHeadlessMasksBeforeSelectingOutputTail(t *testing.T) {
	for _, stream := range []string{"stdout", "stderr"} {
		t.Run(stream, func(t *testing.T) {
			a, st := testAgent(t, "http://127.0.0.1:1", nil)
			a.mask = func(s string) (string, bool) {
				if strings.Contains(s, "BEGIN-SYNTHETIC-SECRET") {
					return "[REDACTED]", true
				}
				return s, true
			}
			dir := t.TempDir()
			text := "BEGIN-SYNTHETIC-SECRET\n" + strings.Repeat("synthetic-key-body\n", 80) + "END-SYNTHETIC-SECRET"
			script := "printf '%s' " + shellQuote(text)
			if stream == "stderr" {
				script += " >&2; exit 1"
			}
			run := model.SysAgentRun{TS: time.Now(), Harness: "local", Workdir: dir, Status: "running"}
			run.ID = st.PutSysAgentRun(run)
			a.running = run.ID
			a.wg.Add(1)
			a.runHeadless(0, run, "/bin/sh", launch{Args: []string{"-c", script}}, time.Second)
			got := st.SysAgentRuns(1)[0]
			if strings.Contains(got.Output+got.Detail, "synthetic-key-body") {
				t.Fatal("selecting a tail removed the context needed for redaction")
			}
		})
	}
}

func TestHeadlessWithholdsTruncatedOutput(t *testing.T) {
	a, st := testAgent(t, "http://127.0.0.1:1", nil)
	dir := t.TempDir()
	fixture := filepath.Join(dir, "output")
	if err := os.WriteFile(fixture, []byte(strings.Repeat("synthetic-key-body", 70000)), 0600); err != nil {
		t.Fatal(err)
	}
	run := model.SysAgentRun{TS: time.Now(), Harness: "local", Workdir: dir, Status: "running"}
	run.ID = st.PutSysAgentRun(run)
	a.running = run.ID
	a.wg.Add(1)
	a.runHeadless(0, run, "/bin/cat", launch{Args: []string{fixture}}, time.Second)
	got := st.SysAgentRuns(1)[0]
	if strings.Contains(got.Output, "synthetic-key-body") || !strings.Contains(got.Output, "withheld") {
		t.Fatal("truncated output was persisted")
	}
}

func TestAnswerFileReadIsBounded(t *testing.T) {
	file := filepath.Join(t.TempDir(), "answer")
	if err := os.WriteFile(file, []byte(strings.Repeat("x", maxOutput+1)), 0600); err != nil {
		t.Fatal(err)
	}
	got := answerText("codex", "progress", file)
	if len(got) > 1024 || !strings.Contains(got, "withheld") {
		t.Fatalf("oversized answer was returned (%d bytes)", len(got))
	}
}
