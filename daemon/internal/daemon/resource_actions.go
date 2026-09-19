package daemon

import (
	"fmt"
	"sort"
	"syscall"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
)

type resourceTerminateFunc func(resource.ControlAction) error
type resourceSignalFunc func(int32, syscall.Signal) error
type resourcePriorityFunc func(int32, int) error

func applyResourceProcessAction(action resource.ControlAction, infos map[int32]agents.AgentInfo,
	terminate resourceTerminateFunc, signal resourceSignalFunc, priority resourcePriorityFunc) error {
	if action.Kind == string(resource.ActionNotify) {
		return nil
	}
	target, ok := infos[action.TargetPID]
	if !ok {
		return fmt.Errorf("target pid is no longer a recognized agent process")
	}
	if !action.TargetStartedAt.IsZero() && !target.StartedAt.Equal(action.TargetStartedAt) {
		return fmt.Errorf("target pid start time changed")
	}
	rootPID := action.RootPID
	if rootPID == 0 {
		rootPID = normalizedActionRoot(target)
	}
	var pids []int32
	for pid, info := range infos {
		if normalizedActionRoot(info) == rootPID {
			pids = append(pids, pid)
		}
	}
	if len(pids) == 0 {
		return fmt.Errorf("session has no recognized live processes")
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	switch resource.InterventionAction(action.Kind) {
	case resource.ActionTerminate:
		if terminate == nil {
			return fmt.Errorf("termination is unavailable")
		}
		return terminate(action)
	case resource.ActionLowerPriority:
		if priority == nil {
			return fmt.Errorf("priority control is unavailable")
		}
		for _, pid := range pids {
			if err := priority(pid, action.Nice); err != nil {
				return fmt.Errorf("lower priority for pid %d: %w", pid, err)
			}
		}
	case resource.ActionPause, resource.ActionResume:
		if signal == nil {
			return fmt.Errorf("process signaling is unavailable")
		}
		sig := syscall.SIGSTOP
		if action.Kind == string(resource.ActionResume) {
			sig = syscall.SIGCONT
		}
		var completed []int32
		for _, pid := range pids {
			if err := signal(pid, sig); err != nil {
				if sig == syscall.SIGSTOP {
					var rollbackErr error
					for _, stoppedPID := range completed {
						if resumeErr := signal(stoppedPID, syscall.SIGCONT); resumeErr != nil && rollbackErr == nil {
							rollbackErr = fmt.Errorf("resume pid %d: %w", stoppedPID, resumeErr)
						}
					}
					if rollbackErr != nil {
						return &resource.PartialPauseError{Cause: fmt.Errorf("signal pid %d: %w; rollback failed: %v", pid, err, rollbackErr)}
					}
				}
				return fmt.Errorf("signal pid %d: %w", pid, err)
			}
			completed = append(completed, pid)
		}
	default:
		return fmt.Errorf("unsupported resource action %q", action.Kind)
	}
	return nil
}

func normalizedActionRoot(info agents.AgentInfo) int32 {
	if info.RootPID != 0 {
		return info.RootPID
	}
	return info.PID
}
