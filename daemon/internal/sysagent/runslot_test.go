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

func TestRunSlotClaimsOneRunAtATime(t *testing.T) {
	a, _ := testAgent(t, "http://127.0.0.1:1", nil)
	if err := a.claimRun(7); err != nil || a.runningID() != 7 {
		t.Fatalf("first claim: id=%d err=%v", a.runningID(), err)
	}
	err := a.claimRun(8)
	if !errors.Is(err, ErrBusy) || !strings.Contains(err.Error(), "run 7 is still running") || a.runningID() != 7 {
		t.Fatalf("second claim: id=%d err=%v", a.runningID(), err)
	}
	a.releaseRun()
	if err := a.claimRun(8); err != nil || a.runningID() != 8 {
		t.Fatalf("claim after release: id=%d err=%v", a.runningID(), err)
	}
}

func TestEntryPointsRefuseWhileRunSlotIsTaken(t *testing.T) {
	ol := newFakeOllama(t, "0.15.1", "qwen3-coder:latest")
	bins := t.TempDir()
	codex := fakeBin(t, bins, "codex", "echo progress\n")
	a, st := testAgent(t, ol.URL, map[string]string{"codex": codex})
	work := t.TempDir()
	p, err := a.SavePlan(PlanInput{Title: "Slot", Harness: "codex", Mode: ModeHeadless, Workdir: work, Task: "Hold the slot"})
	if err != nil {
		t.Fatal(err)
	}
	msg := model.SysAgentMessage{TS: time.Now(), Role: "assistant", Content: "run it",
		LocalCommand: &model.SysAgentLocalCommand{Command: "echo hi", Workdir: work, Mode: ModeHeadless}}
	msg.ID = st.PutSysAgentMessage(msg)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "AGENTS.md"), []byte("# rules\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	preview, err := a.PreviewInstruction(dir, "codex", "secret-in-transcript")
	if err != nil {
		t.Fatal(err)
	}

	a.mu.Lock()
	if err := a.claimRun(99); err != nil {
		t.Fatal(err)
	}
	a.mu.Unlock()
	refusals := map[string]error{}
	_, refusals["Dispatch"] = a.Dispatch(context.Background(), DispatchInput{PlanID: p.ID})
	_, refusals["RunLocal"] = a.RunLocal(msg.ID)
	_, refusals["ApplyInstruction"] = a.ApplyInstruction(dir, "codex", "secret-in-transcript", preview.Revision)
	for name, err := range refusals {
		if !errors.Is(err, ErrBusy) || !strings.Contains(err.Error(), "run 99 is still running; one headless run at a time") {
			t.Errorf("%s while the slot is taken: %v", name, err)
		}
	}

	a.mu.Lock()
	a.releaseRun()
	a.mu.Unlock()
	if _, err := a.RunLocal(msg.ID); err != nil {
		t.Fatalf("RunLocal after release: %v", err)
	}
	a.Wait()
	if _, err := a.Dispatch(context.Background(), DispatchInput{PlanID: p.ID}); err != nil {
		t.Fatalf("Dispatch after the headless run ended: %v", err)
	}
	a.Wait()
	if a.runningID() != 0 {
		t.Fatalf("slot still taken after the run ended: %d", a.runningID())
	}
}

func TestLaunchFolder(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	const narrower = "a headless run needs a folder narrower than /; pick one, or open it in a terminal"
	for _, tc := range []struct {
		name, mode, workdir, want string
	}{
		{"missing", ModeHeadless, filepath.Join(dir, "gone"), "the folder " + filepath.Join(dir, "gone") + " does not exist"},
		{"file", ModeTerminal, file, "the folder " + file + " does not exist"},
		{"headless root", ModeHeadless, "/", narrower},
	} {
		err := launchFolder(tc.mode, tc.workdir)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	if err := launchFolder(ModeTerminal, "/"); err != nil {
		t.Errorf("terminal in /: %v", err)
	}
	if err := launchFolder(ModeHeadless, dir); err != nil {
		t.Errorf("headless in a real folder: %v", err)
	}
}
