package daemon

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestResourceExecutorRejectsLivePIDReuseWithoutTaggerRefresh(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "events.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	started := time.Now().Add(-time.Minute)
	const pid int32 = 2147483000
	procs := mapProcSource{pid: {PID: pid, PPID: 1, Comm: "claude", Exe: "/usr/local/bin/claude", CWD: "/workspace", StartTime: started}}
	tagger := agents.New(config.Config{Agents: []config.AgentDef{{Name: "claude", Match: []string{"claude"}}}}, procs)
	tagger.Refresh()
	if _, ok := tagger.TaggedPIDs()[pid]; !ok {
		t.Fatal("fixture was not attributed")
	}
	procs[pid] = agents.ProcInfo{PID: pid, PPID: 1, Comm: "claude", Exe: "/usr/local/bin/claude", CWD: "/workspace", StartTime: started.Add(time.Second)}
	err = makeResourceExecutor(nil, tagger, procs, st)(resource.ControlAction{Kind: "resume", RootPID: pid, RootStartedAt: started, TargetPID: pid, TargetStartedAt: started})
	if err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("live identity was not checked before signaling: %v", err)
	}
}

func TestApplyResourceProcessActionTargetsWholeRecognizedFamily(t *testing.T) {
	started := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	infos := map[int32]agents.AgentInfo{
		10: {PID: 10, RootPID: 10, StartedAt: started},
		11: {PID: 11, RootPID: 10, StartedAt: started.Add(time.Second)},
		99: {PID: 99, RootPID: 99, StartedAt: started},
	}
	var signaled []int32
	err := applyResourceProcessAction(resource.ControlAction{Kind: "pause", RootPID: 10, TargetPID: 10, TargetStartedAt: started}, infos,
		nil, func(pid int32, signal syscall.Signal) error {
			if signal != syscall.SIGSTOP {
				t.Fatalf("signal=%v", signal)
			}
			signaled = append(signaled, pid)
			return nil
		}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(signaled) != "[10 11]" {
		t.Fatalf("signaled=%v", signaled)
	}
}

func TestApplyResourceProcessActionRejectsReusedTargetPID(t *testing.T) {
	started := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	infos := map[int32]agents.AgentInfo{10: {PID: 10, RootPID: 10, StartedAt: started.Add(time.Second)}}
	called := false
	err := applyResourceProcessAction(resource.ControlAction{Kind: "pause", RootPID: 10, TargetPID: 10, TargetStartedAt: started}, infos,
		nil, func(int32, syscall.Signal) error { called = true; return nil }, nil)
	if err == nil || called {
		t.Fatalf("err=%v called=%v", err, called)
	}
}

func TestApplyResourceProcessActionRollsBackPartialPause(t *testing.T) {
	started := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	infos := map[int32]agents.AgentInfo{
		10: {PID: 10, RootPID: 10, StartedAt: started},
		11: {PID: 11, RootPID: 10, StartedAt: started},
	}
	var calls []string
	err := applyResourceProcessAction(resource.ControlAction{Kind: "pause", RootPID: 10, TargetPID: 10, TargetStartedAt: started}, infos,
		nil, func(pid int32, signal syscall.Signal) error {
			calls = append(calls, fmt.Sprintf("%d:%d", pid, signal))
			if pid == 11 && signal == syscall.SIGSTOP {
				return fmt.Errorf("denied")
			}
			return nil
		}, nil)
	if err == nil {
		t.Fatal("partial pause reported success")
	}
	want := fmt.Sprintf("[10:%d 11:%d 10:%d]", syscall.SIGSTOP, syscall.SIGSTOP, syscall.SIGCONT)
	if fmt.Sprint(calls) != want {
		t.Fatalf("calls=%v", calls)
	}
}

func TestApplyResourceProcessActionReportsFailedPauseRollback(t *testing.T) {
	started := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	infos := map[int32]agents.AgentInfo{
		10: {PID: 10, RootPID: 10, StartedAt: started},
		11: {PID: 11, RootPID: 10, StartedAt: started},
	}
	err := applyResourceProcessAction(resource.ControlAction{Kind: "pause", RootPID: 10, TargetPID: 10, TargetStartedAt: started}, infos,
		nil, func(pid int32, signal syscall.Signal) error {
			if pid == 11 && signal == syscall.SIGSTOP {
				return fmt.Errorf("pause denied")
			}
			if pid == 10 && signal == syscall.SIGCONT {
				return fmt.Errorf("resume denied")
			}
			return nil
		}, nil)
	var partial *resource.PartialPauseError
	if !errors.As(err, &partial) {
		t.Fatalf("err=%v want PartialPauseError", err)
	}
}

func TestApplyResourceProcessActionLowersPriority(t *testing.T) {
	started := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	infos := map[int32]agents.AgentInfo{10: {PID: 10, RootPID: 10, StartedAt: started}}
	var gotPID int32
	var gotNice int
	err := applyResourceProcessAction(resource.ControlAction{Kind: "lower_priority", RootPID: 10, TargetPID: 10, TargetStartedAt: started, Nice: 12}, infos,
		nil, nil, func(pid int32, nice int) error { gotPID, gotNice = pid, nice; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if gotPID != 10 || gotNice != 12 {
		t.Fatalf("pid=%d nice=%d", gotPID, gotNice)
	}
}

func TestResourceFamilyPartialPriorityAndResumeAreNotPlainFailures(t *testing.T) {
	started := time.Now()
	infos := map[int32]agents.AgentInfo{10: {PID: 10, RootPID: 10, StartedAt: started}, 11: {PID: 11, RootPID: 10, StartedAt: started}}
	for _, kind := range []string{"lower_priority", "resume"} {
		t.Run(kind, func(t *testing.T) {
			failSecond := func(pid int32) error {
				if pid == 11 {
					return fmt.Errorf("denied")
				}
				return nil
			}
			err := applyResourceProcessAction(resource.ControlAction{Kind: kind, RootPID: 10, TargetPID: 10, TargetStartedAt: started}, infos, nil, func(pid int32, _ syscall.Signal) error { return failSecond(pid) }, func(pid int32, _ int) error { return failSecond(pid) })
			var partial *resource.PartialActionError
			if !errors.As(err, &partial) {
				t.Fatalf("partial family change lost: %v", err)
			}
		})
	}
}

func TestResourceActionCannotUseTargetFromDifferentRoot(t *testing.T) {
	started := time.Now()
	called := false
	infos := map[int32]agents.AgentInfo{10: {PID: 10, RootPID: 10, StartedAt: started}, 20: {PID: 20, RootPID: 20, StartedAt: started}}
	err := applyResourceProcessAction(resource.ControlAction{Kind: "pause", RootPID: 20, TargetPID: 10, TargetStartedAt: started}, infos, nil, func(int32, syscall.Signal) error { called = true; return nil }, nil)
	if err == nil || called {
		t.Fatalf("unapproved family signaled: err=%v called=%v", err, called)
	}
}
