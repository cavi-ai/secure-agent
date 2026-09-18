package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type killRequest struct {
	PID       int32  `json:"pid"`
	StartedAt string `json:"started_at,omitempty"`
}

// agentPIDs supplies the live tagged-agent pid set for /kill allowlisting;
// nil disables the restriction (unit tests, non-darwin builds).
func (a *API) SetAgentPIDs(fn func() map[int32]struct{}) {
	a.agentPIDs = fn
}

func (a *API) handleKill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limitBody(w, r)
	var req killRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PID <= 0 {
		http.Error(w, "Invalid pid", http.StatusBadRequest)
		return
	}

	killed, err := a.TerminateAgentTree(req.PID, req.StartedAt)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not a recognized") {
			status = http.StatusForbidden
		}
		if strings.Contains(err.Error(), "no longer") || strings.Contains(err.Error(), "start") {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
	writeJSON(w, map[string]interface{}{"status": "ok", "pid": req.PID, "killed": killed})
}

// TerminateAgentTree is the single guarded containment path used by both the
// operator /kill endpoint and resource budgets.
func (a *API) TerminateAgentTree(pid int32, startedAt string) ([]int32, error) {
	return a.terminateAgentTree(pid, startedAt, nil)
}

// TerminateAgentTreeVerified applies the normal guarded containment path and
// additionally proves every family member is the same process instance seen
// by the resource sampler.
func (a *API) TerminateAgentTreeVerified(pid int32, startedAt string, expectedStarts map[int32]time.Time) ([]int32, error) {
	return a.terminateAgentTree(pid, startedAt, expectedStarts)
}

func (a *API) terminateAgentTree(pid int32, startedAt string, expectedStarts map[int32]time.Time) ([]int32, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid pid")
	}
	// A control socket that can kill any pid is a self-neutralization
	// primitive (kill the daemon, kill an unrelated user process). Only
	// processes the tagger currently recognizes as agents are valid targets.
	// Re-checked immediately before the kill: between the first check and the
	// signal, the agent can exit and the pid can be recycled by an unrelated
	// process. started_at from the client is compared to the live tagged
	// process so a recycled pid with a different start time is refused.
	if a.agentPIDs != nil {
		if _, ok := a.agentPIDs()[pid]; !ok {
			return nil, fmt.Errorf("pid is not a recognized agent process tree")
		}
		// Re-verify right before signaling to shrink the pid-reuse window.
		if _, ok := a.agentPIDs()[pid]; !ok {
			return nil, fmt.Errorf("pid is no longer a recognized agent process")
		}
	}

	if startedAt != "" {
		if err := a.checkKillStart(pid, startedAt); err != nil {
			return nil, err
		}
	}

	// UI copy, CLI, and flag actions all say "process tree". Kill every
	// currently tagged agent that shares this pid's root_pid — not the OS
	// process tree, only what the tagger already recognized.
	var members []int32
	for _, memberPID := range a.killTreePIDs(pid) {
		if a.agentPIDs != nil {
			if _, ok := a.agentPIDs()[memberPID]; !ok {
				continue
			}
		}
		members = append(members, memberPID)
	}
	if expectedStarts != nil {
		for _, memberPID := range members {
			if err := a.checkExpectedProcessStart(memberPID, expectedStarts); err != nil {
				return nil, err
			}
		}
	}
	var killed []int32
	for _, memberPID := range members {
		if expectedStarts != nil {
			if err := a.checkExpectedProcessStart(memberPID, expectedStarts); err != nil {
				return killed, err
			}
		}
		if err := a.killer.Kill(memberPID); err != nil {
			return killed, fmt.Errorf("Kill failed: %w", err)
		}
		killed = append(killed, memberPID)
	}
	return killed, nil
}

func (a *API) checkExpectedProcessStart(pid int32, expected map[int32]time.Time) error {
	want, ok := expected[pid]
	if !ok || want.IsZero() {
		return fmt.Errorf("pid %d has no verified start identity", pid)
	}
	for _, ag := range a.statusFn().Agents {
		if ag.PID != pid {
			continue
		}
		got, err := time.Parse(time.RFC3339Nano, ag.StartedAt)
		if err != nil || !got.Equal(want) {
			return fmt.Errorf("pid %d start time mismatch (process recycled?)", pid)
		}
		return nil
	}
	return fmt.Errorf("pid %d is no longer in the recognized session", pid)
}

func (a *API) killTreePIDs(pid int32) []int32 {
	st := a.statusFn()
	root := pid
	found := false
	for _, ag := range st.Agents {
		if ag.PID != pid {
			continue
		}
		found = true
		if ag.RootPID != 0 {
			root = ag.RootPID
		}
		break
	}
	if !found {
		return []int32{pid}
	}
	var helpers, roots []int32
	seen := map[int32]struct{}{}
	for _, ag := range st.Agents {
		r := ag.RootPID
		if r == 0 {
			r = ag.PID
		}
		if r != root {
			continue
		}
		if _, ok := seen[ag.PID]; ok {
			continue
		}
		seen[ag.PID] = struct{}{}
		if ag.PID == root {
			roots = append(roots, ag.PID)
		} else {
			helpers = append(helpers, ag.PID)
		}
	}
	if len(roots) == 0 {
		roots = []int32{root}
	}
	return append(helpers, roots...)
}

func (a *API) checkKillStart(pid int32, startedAt string) error {
	st := a.statusFn()
	for _, ag := range st.Agents {
		if ag.PID != pid {
			continue
		}
		if ag.StartedAt != "" && ag.StartedAt != startedAt {
			return fmt.Errorf("pid %d start time mismatch (process recycled?)", pid)
		}
		return nil
	}
	return nil
}
