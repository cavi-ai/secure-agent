package sysagent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// A predictable command path keeps daemon credentials out of the child while
// still finding system and common macOS package-manager tools.
const localCommandPath = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

// RunLocal executes only the exact command in a stored assistant proposal.
// The API accepts a message id, never a command supplied by the caller.
// The console shows the command and asks for confirmation before this call.
func (a *Agent) RunLocal(messageID int64) (model.SysAgentRun, error) {
	cfg := a.config()
	if !cfg.Enabled {
		return model.SysAgentRun{}, ErrDisabled
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	m, ok := a.st.GetSysAgentMessage(messageID)
	if !ok || m.Role != "assistant" || m.LocalCommand == nil {
		return model.SysAgentRun{}, ErrNotFound
	}
	if m.LocalRunID != 0 {
		return model.SysAgentRun{}, fmt.Errorf("%w: this command has already been started", ErrBusy)
	}
	if a.running != 0 {
		return model.SysAgentRun{}, fmt.Errorf("%w: another local run is in progress", ErrBusy)
	}
	action := m.LocalCommand
	if (action.Mode != ModeHeadless && action.Mode != ModeTerminal) || strings.TrimSpace(action.Command) == "" || len(action.Command) > 2048 {
		return model.SysAgentRun{}, fmt.Errorf("%w: invalid stored local command", ErrInvalid)
	}
	if fi, err := os.Stat(action.Workdir); err != nil || !fi.IsDir() {
		return model.SysAgentRun{}, fmt.Errorf("%w: the folder %s does not exist", ErrInvalid, action.Workdir)
	}
	if action.Mode == ModeHeadless && action.Workdir == string(filepath.Separator) {
		return model.SysAgentRun{}, fmt.Errorf("%w: a headless command needs a folder narrower than /", ErrInvalid)
	}
	run := model.SysAgentRun{TS: a.now(), Title: "Local command", Harness: "local", Mode: action.Mode,
		Workdir: action.Workdir, Command: action.Command, Model: cfg.Model}
	var script string
	if action.Mode == ModeTerminal {
		if err := os.MkdirAll(a.stateDir, 0o700); err != nil {
			return model.SysAgentRun{}, err
		}
		script = filepath.Join(a.stateDir, fmt.Sprintf("local-%d-%d%s", messageID, run.TS.UnixNano(), scriptExt))
		body := "#!/bin/sh\nrm -f -- \"$0\"\ncd -- " + shellQuote(action.Workdir) + " || exit 1\n" +
			"exec env -i PATH=" + localCommandPath + " HOME=" + shellQuote(a.home) +
			" USER=" + shellQuote(os.Getenv("USER")) + " /bin/sh -c " + shellQuote(action.Command) + "\n"
		if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
			return model.SysAgentRun{}, fmt.Errorf("write local command script: %w", err)
		}
		run.Status, run.Detail = "manual", "Run in a terminal: sh "+shellQuote(script)
	} else {
		run.Status = "running"
	}
	if !a.st.ClaimSysAgentAction(messageID) {
		if script != "" {
			_ = os.Remove(script)
		}
		return model.SysAgentRun{}, fmt.Errorf("%w: command could not be claimed or was already started", ErrBusy)
	}
	run.ID = a.st.PutSysAgentRun(run)
	if run.ID == 0 {
		if script != "" {
			_ = os.Remove(script)
		}
		return model.SysAgentRun{}, fmt.Errorf("%w: command run could not be recorded", ErrUnavailable)
	}
	m.LocalRunID = run.ID
	a.st.PutSysAgentMessage(m)
	a.st.PutAudit(store.AuditEntry{Action: "sysagent-local-command", Detail: fmt.Sprintf("message=%d run=%d mode=%s folder=%s status=%s", messageID, run.ID, run.Mode, run.Workdir, run.Status)})
	if action.Mode == ModeTerminal && a.openTerminal != nil {
		if err := a.openTerminal(script); err != nil {
			run.Detail = "Terminal did not open (" + err.Error() + "). Run: sh " + shellQuote(script)
		} else {
			run.Status, run.Detail = "opened", "Opened in Terminal; the command runs there"
		}
		a.st.PutSysAgentRun(run)
	}
	if action.Mode == ModeHeadless {
		a.running = run.ID
		a.wg.Add(1)
		go a.runHeadless(0, run, "/bin/sh", launch{
			Args:  []string{"-c", action.Command},
			Unset: inheritedEnvKeys(),
			Env:   []string{"PATH=" + localCommandPath, "HOME=" + a.home, "USER=" + os.Getenv("USER")},
		}, time.Duration(cfg.TimeoutMinutes)*time.Minute)
	}
	return run, nil
}

// inheritedEnvKeys prevents secrets and provider credentials in the daemon's
// environment from being inherited by an arbitrary local command.
func inheritedEnvKeys() []string {
	var keys []string
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		keys = append(keys, key)
	}
	return keys
}
