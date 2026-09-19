package daemon

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
)

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
