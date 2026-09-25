package sysagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/toolpath"
)

// DispatchInput names the plan to dispatch and, optionally, a mode, folder
// or model for this dispatch (kept on the plan).
type DispatchInput struct {
	PlanID  int64  `json:"plan_id"`
	Mode    string `json:"mode"`
	Workdir string `json:"workdir"`
	Model   string `json:"model"`
}

// maxOutput bounds what a headless run's output keeps in memory;
// outputLines is the tail stored.
const (
	maxOutput   = 1 << 20
	outputLines = 60
)

// Dispatch runs a plan's harness against the local Ollama: headless in the
// plan's folder (one at a time, the result lands in the store), or in a
// terminal the operator drives. A harness that cannot run now leaves the
// plan saved with the reason.
func (a *Agent) Dispatch(ctx context.Context, in DispatchInput) (model.SysAgentRun, error) {
	cfg := a.config()
	if !cfg.Enabled {
		return model.SysAgentRun{}, ErrDisabled
	}
	p, ok := a.st.GetSysAgentPlan(in.PlanID)
	if !ok {
		return model.SysAgentRun{}, ErrNotFound
	}
	if p.Status == "running" {
		return model.SysAgentRun{}, fmt.Errorf("%w: plan %d is running", ErrBusy, p.ID)
	}
	if in.Mode != "" {
		p.Mode = in.Mode
	}
	if in.Workdir != "" {
		p.Workdir = in.Workdir
	}
	if in.Model != "" {
		p.Model = in.Model
	}
	if err := a.normalizePlan(&p); err != nil {
		return model.SysAgentRun{}, err
	}
	if fi, err := os.Stat(p.Workdir); err != nil || !fi.IsDir() {
		return model.SysAgentRun{}, fmt.Errorf("%w: the folder %s does not exist", ErrInvalid, p.Workdir)
	}
	h, _ := harnessByID(p.Harness)
	info := probe(ctx, a.client, cfg.Endpoint)
	modelName := harnessModel(cfg, info, p.Model)
	if reason := a.harnessReason(cfg, info, h, modelName); reason != "" {
		p.Note = reason
		a.st.PutSysAgentPlan(p)
		return model.SysAgentRun{}, fmt.Errorf("%w: %s; the plan stays saved", ErrUnavailable, reason)
	}
	bin := a.look(h.Bin)
	if err := os.MkdirAll(a.stateDir, 0o700); err != nil {
		return model.SysAgentRun{}, fmt.Errorf("state folder: %w", err)
	}
	now := a.now()
	task := composeTask(p)
	l, err := buildLaunch(h.ID, p.Mode, launchSpec{Endpoint: cfg.Endpoint, Model: modelName, Workdir: p.Workdir, Task: task,
		StateDir: a.stateDir, Tag: fmt.Sprintf("%d-%d", p.ID, now.UnixNano()), TimeoutSec: cfg.TimeoutMinutes * 60})
	if err != nil {
		return model.SysAgentRun{}, err
	}
	run := model.SysAgentRun{PlanID: p.ID, TS: now, Title: p.Title, Harness: h.ID, Mode: p.Mode, Model: modelName,
		Workdir: p.Workdir, Command: commandLine(bin, l, task)}
	if p.Mode == ModeTerminal {
		return a.dispatchTerminal(p, run, bin, l)
	}
	a.mu.Lock()
	if a.running != 0 {
		busy := a.running
		a.mu.Unlock()
		return model.SysAgentRun{}, fmt.Errorf("%w: run %d is still running; one headless run at a time", ErrBusy, busy)
	}
	if err := writeFiles(l.Files); err != nil {
		a.mu.Unlock()
		return model.SysAgentRun{}, err
	}
	run.Status = "running"
	run.ID = a.st.PutSysAgentRun(run)
	a.running = run.ID
	a.wg.Add(1)
	a.mu.Unlock()
	p.Status, p.RunID, p.Note = "running", run.ID, ""
	a.st.PutSysAgentPlan(p)
	a.audit(run)
	go a.runHeadless(p.ID, run, bin, l, time.Duration(cfg.TimeoutMinutes)*time.Minute)
	return run, nil
}

// composeTask is what the harness receives: the ground rules, the plan and
// the procedures of its skills. It never starts with "-", so no harness
// reads it as a flag.
func composeTask(p model.SysAgentPlan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "You are running on a local model through secure-agent's system agent. Work in %s. "+
		"Never print, copy or send secret values (passwords, tokens, private keys, passphrases); a command that needs one must prompt for it. "+
		"Do not disable or bypass secure-agent, its hooks, guard or firewall.\n\n", p.Workdir)
	fmt.Fprintf(&b, "Task: %s\n%s\n", p.Title, p.Task)
	if len(p.Steps) > 0 {
		b.WriteString("\nSteps:\n")
		for i, s := range p.Steps {
			fmt.Fprintf(&b, "%d. %s\n", i+1, s)
		}
	}
	if len(p.Skills) > 0 {
		b.WriteString("\nReference procedures from secure-agent (follow them):\n")
		for _, id := range p.Skills {
			if s, ok := skillByID(id); ok {
				fmt.Fprintf(&b, "\n<skill id=%q>\n%s\n</skill>\n", s.ID, s.Body)
			}
		}
	}
	return b.String()
}

// writeFiles writes a launch's files, owner-only.
func writeFiles(files map[string][]byte) error {
	for path, data := range files {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", filepath.Base(path), err)
		}
	}
	return nil
}

func removeFiles(l launch) {
	for path := range l.Files {
		_ = os.Remove(path)
	}
	if l.AnswerFile != "" {
		_ = os.Remove(l.AnswerFile)
	}
}

func (a *Agent) audit(run model.SysAgentRun) {
	a.st.PutAudit(store.AuditEntry{Action: "sysagent-dispatch", Detail: fmt.Sprintf("plan=%d run=%d harness=%s mode=%s model=%s folder=%s status=%s",
		run.PlanID, run.ID, run.Harness, run.Mode, run.Model, run.Workdir, run.Status)})
}

// runHeadless runs the harness in its own process group under the timeout
// and records the outcome on the run and its plan.
func (a *Agent) runHeadless(planID int64, run model.SysAgentRun, bin string, l launch, timeout time.Duration) {
	defer func() {
		a.mu.Lock()
		a.running = 0
		a.mu.Unlock()
		a.wg.Done()
	}()
	defer removeFiles(l)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := toolpath.Command(ctx, bin, a.binDirs, l.Args...)
	cmd.Dir = run.Workdir
	cmd.Env = mergeEnv(cmd.Env, l.Env, l.Unset)
	var out, errOut limitedBuffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	runErr := cmd.Run()

	text := answerText(run.Harness, out.String(), l.AnswerFile)
	fin := a.now()
	run.FinishedAt = &fin
	var exitErr *exec.ExitError
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		run.Status, run.Detail = "timeout", fmt.Sprintf("stopped after %v", timeout)
	case runErr != nil:
		run.Status, run.Detail = "failed", strings.TrimSpace(runErr.Error()+": "+tail(errOut.String(), 6))
		if errors.As(runErr, &exitErr) {
			run.ExitCode = exitErr.ExitCode()
		}
	default:
		run.Status = "done"
	}
	if strings.TrimSpace(text) == "" {
		text = errOut.String()
	}
	run.Output = tail(text, outputLines)
	if !a.maskAll(&run.Output) {
		run.Output = "[output withheld: it held a secret that could not be masked]"
	}
	if !a.maskAll(&run.Detail) {
		run.Detail = "[detail withheld: it held a secret that could not be masked]"
	}
	a.st.PutSysAgentRun(run)
	if p, ok := a.st.GetSysAgentPlan(planID); ok {
		p.Status = "done"
		if run.Status != "done" {
			p.Status = "failed"
		}
		a.st.PutSysAgentPlan(p)
	}
	a.audit(run)
}

// answerText is the harness's final answer: Claude Code's JSON result, the
// file Codex wrote, or what the others printed.
func answerText(harness, stdout, answerFile string) string {
	switch harness {
	case "claude":
		var r struct {
			Result string `json:"result"`
		}
		if json.Unmarshal([]byte(strings.TrimSpace(stdout)), &r) == nil && r.Result != "" {
			return r.Result
		}
	case "codex":
		if answerFile != "" {
			if b, err := os.ReadFile(answerFile); err == nil && len(bytes.TrimSpace(b)) > 0 {
				return string(b)
			}
		}
	}
	return stdout
}

// dispatchTerminal writes a script that runs the harness interactively and
// opens it in a terminal window; where none can open, the operator runs it.
func (a *Agent) dispatchTerminal(p model.SysAgentPlan, run model.SysAgentRun, bin string, l launch) (model.SysAgentRun, error) {
	if err := writeFiles(l.Files); err != nil {
		return run, err
	}
	script := filepath.Join(a.stateDir, fmt.Sprintf("terminal-%d-%d%s", p.ID, run.TS.UnixNano(), scriptExt))
	if err := os.WriteFile(script, []byte(terminalScript(p.ID, run, bin, l)), 0o700); err != nil {
		removeFiles(l)
		return run, fmt.Errorf("write the terminal script: %w", err)
	}
	run.Status, run.Detail = "manual", "Run it in a terminal: sh "+shellQuote(script)
	if a.openTerminal != nil {
		if err := a.openTerminal(script); err != nil {
			run.Detail = "The terminal did not open (" + err.Error() + "). Run it yourself: sh " + shellQuote(script)
		} else {
			run.Status, run.Detail = "opened", "Opened in Terminal"
		}
	}
	run.ID = a.st.PutSysAgentRun(run)
	p.Status, p.RunID, p.Note = run.Status, run.ID, ""
	a.st.PutSysAgentPlan(p)
	a.audit(run)
	return run, nil
}

// terminalScript runs the harness in the plan's folder with the launch's
// environment, then removes the launch's files. It deletes itself first:
// the task it carries is not left behind.
func terminalScript(planID int64, run model.SysAgentRun, bin string, l launch) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	fmt.Fprintf(&b, "# secure-agent system agent: plan %d, %s on local Ollama (model %s).\n", planID, run.Harness, oneLine(run.Model))
	b.WriteString("rm -f -- \"$0\"\n")
	fmt.Fprintf(&b, "cd -- %s || exit 1\n", shellQuote(run.Workdir))
	if len(l.Unset) > 0 {
		fmt.Fprintf(&b, "unset %s\n", strings.Join(l.Unset, " "))
	}
	for _, kv := range l.Env {
		k, v, _ := strings.Cut(kv, "=")
		if k == "NO_PROXY" { // keep the operator's own entries after the loopback hosts
			fmt.Fprintf(&b, "export NO_PROXY=%s\"${NO_PROXY:+,$NO_PROXY}\"\n", shellQuote(v))
			continue
		}
		fmt.Fprintf(&b, "export %s=%s\n", k, shellQuote(v))
	}
	fmt.Fprintf(&b, "printf '%%s\\n' %s\n", shellQuote(fmt.Sprintf("secure-agent: %s on local Ollama (%s) in %s — plan %d", run.Harness, run.Model, run.Workdir, planID)))
	args := make([]string, 0, len(l.Args)+1)
	args = append(args, shellQuote(bin))
	for _, arg := range l.Args {
		args = append(args, shellQuote(arg))
	}
	b.WriteString(strings.Join(args, " ") + "\n")
	b.WriteString("status=$?\n")
	var files []string
	for path := range l.Files {
		files = append(files, shellQuote(path))
	}
	if len(files) > 0 {
		fmt.Fprintf(&b, "rm -f -- %s\n", strings.Join(files, " "))
	}
	b.WriteString("exit $status\n")
	return b.String()
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// limitedBuffer keeps the first maxOutput bytes written to it.
type limitedBuffer struct{ b bytes.Buffer }

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := maxOutput - l.b.Len(); room > 0 {
		if len(p) > room {
			l.b.Write(p[:room])
		} else {
			l.b.Write(p)
		}
	}
	return len(p), nil
}

func (l *limitedBuffer) String() string { return l.b.String() }
