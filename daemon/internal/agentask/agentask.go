// Package agentask asks the agent that owns a worktree to sort it out: the
// daemon resumes that agent's own conversation (Claude Code or Codex, by
// the session id its hook or transcript recorded) in the worktree with a
// fixed request — open a pull request for work worth keeping, or say the
// worktree can go — and records the answer.
//
// Invariants:
//   - The request is fixed text built from the checker's facts; nothing the
//     repository contains is sent as instructions.
//   - One ask runs at a time, bounded by a timeout and (Claude Code) a
//     dollar cap; the agent runs with the user's own settings and hooks.
//   - The answer is recorded, never acted on: the worktree's verdict and
//     what removal accepts are computed without it.
package agentask

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/toolpath"
)

const (
	// BudgetUSD caps one Claude Code ask (--max-budget-usd).
	BudgetUSD = 1.00
	// Timeout bounds one ask.
	Timeout = 15 * time.Minute
	// maxOutput bounds the reply kept in memory.
	maxOutput = 1 << 20
)

var (
	// ErrNoSession: no Claude Code or Codex session with a recorded id
	// worked in the worktree.
	ErrNoSession = errors.New("no resumable agent session recorded in this worktree (Claude Code or Codex, identified by its hook or transcript)")
	// ErrBusy: another ask is running.
	ErrBusy = errors.New("an ask is already running; one at a time")
)

// Store is what asks read and record. *store.Store satisfies it.
type Store interface {
	SessionsInWorkspace(dir string) []model.Session
	PutAgentAsk(model.AgentAsk) int64
	FinishAgentAsk(model.AgentAsk)
	PutCleanup(model.CleanupEntry)
	PutAudit(store.AuditEntry)
}

// Request is the checker's view of the worktree the agent is asked about.
type Request struct {
	Path    string
	Repo    string
	Branch  string
	State   string
	Reasons []string
}

// Asker runs asks.
type Asker struct {
	st      Store
	binDirs []string
	now     func() time.Time
	timeout time.Duration

	mu      sync.Mutex
	running bool
	wg      sync.WaitGroup
}

// New builds an asker; home "" resolves to the user's home.
func New(st Store, home string) *Asker {
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	return &Asker{st: st, binDirs: toolpath.Dirs(home), now: time.Now, timeout: Timeout}
}

// WithBinDirs replaces the directories searched for claude and codex after
// the daemon's PATH.
func (a *Asker) WithBinDirs(dirs []string) *Asker {
	a.binDirs = dirs
	return a
}

// Ask resumes the newest resumable session that worked in req.Path and
// returns the running ask; the answer lands in the store.
func (a *Asker) Ask(req Request) (model.AgentAsk, error) {
	var sess model.Session
	for _, s := range a.st.SessionsInWorkspace(req.Path) {
		if s.Harness == "claude" || s.Harness == "codex" {
			sess = s
			break
		}
	}
	if sess.ID == "" {
		return model.AgentAsk{}, ErrNoSession
	}
	bin := toolpath.Look(sess.Harness, a.binDirs)
	if bin == "" {
		return model.AgentAsk{}, fmt.Errorf("the %s CLI is not installed where the daemon can find it", sess.Harness)
	}
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return model.AgentAsk{}, ErrBusy
	}
	a.running = true
	a.wg.Add(1)
	a.mu.Unlock()

	ask := model.AgentAsk{TS: a.now(), Path: req.Path, Repo: req.Repo, Harness: sess.Harness, SessionID: sess.ID, Status: "running"}
	ask.ID = a.st.PutAgentAsk(ask)
	a.st.PutAudit(store.AuditEntry{Action: "worktree-ask", Detail: fmt.Sprintf("path=%s harness=%s session=%s", req.Path, sess.Harness, sess.ID)})
	go a.run(ask, bin, req)
	return ask, nil
}

func (a *Asker) run(ask model.AgentAsk, bin string, req Request) {
	defer a.wg.Done()
	defer func() {
		a.mu.Lock()
		a.running = false
		a.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()

	prompt := Prompt(req)
	var args []string
	var lastFile string
	switch ask.Harness {
	case "claude":
		args = []string{"--resume", ask.SessionID, "--fork-session", "-p", prompt,
			"--output-format", "json", "--max-budget-usd", strconv.FormatFloat(BudgetUSD, 'f', 2, 64)}
	case "codex":
		f, err := os.CreateTemp("", "secure-agent-ask-*.txt")
		if err == nil {
			lastFile = f.Name()
			f.Close()
			defer os.Remove(lastFile)
		}
		args = []string{"exec", "resume", ask.SessionID, prompt, "--skip-git-repo-check"}
		if lastFile != "" {
			args = append(args, "-o", lastFile)
		}
	}
	// Its own process group: a timeout kills the tools the agent started too.
	cmd := toolpath.Command(ctx, bin, a.binDirs, args...)
	cmd.Dir = req.Path
	var out, errOut limitedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	runErr := cmd.Run()

	text, cost := reply(ask.Harness, out.String(), lastFile)
	verdict, detail := ParseVerdict(text)
	fin := a.now()
	ask.FinishedAt, ask.CostUSD, ask.Output = &fin, cost, tail(text, 12)
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		ask.Status, ask.Verdict, ask.Detail = "timeout", "none", fmt.Sprintf("no answer within %v", a.timeout)
	case verdict != "":
		ask.Status, ask.Verdict, ask.Detail = "answered", verdict, detail
	case runErr != nil:
		ask.Status, ask.Verdict, ask.Detail = "failed", "none", strings.TrimSpace(runErr.Error()+": "+tail(errOut.String(), 3))
	default:
		ask.Status, ask.Verdict, ask.Detail = "answered", "none", "the reply had no WORKTREE-VERDICT line"
	}
	a.st.FinishAgentAsk(ask)
	a.st.PutCleanup(model.CleanupEntry{TS: fin, Action: "ask:" + ask.Verdict, Path: ask.Path, Repo: ask.Repo,
		Detail: strings.TrimSpace(ask.Harness + " " + ask.Status + ": " + ask.Detail)})
}

// Prompt is the fixed request the agent receives.
func Prompt(req Request) string {
	var b strings.Builder
	branch := req.Branch
	if branch == "" {
		branch = "a detached HEAD"
	}
	fmt.Fprintf(&b, "secure-agent is tidying git worktrees on this machine. This worktree is one you worked in: %s (%s).\n", req.Path, branch)
	fmt.Fprintf(&b, "The worktree checker marked it %q because:\n", req.State)
	for _, r := range req.Reasons {
		fmt.Fprintf(&b, "- %s\n", r)
	}
	b.WriteString(`Look at what is here and do one of these, then end your reply with exactly one line in the form shown:
- The work matters: commit it, push the branch and open a pull request (or name the one that exists).
  WORKTREE-VERDICT: pr <pull request URL>
- Nothing here is needed anymore: say why in one line.
  WORKTREE-VERDICT: removable <reason>
- It has to stay for now: say why in one line.
  WORKTREE-VERDICT: keep <reason>
Do not delete the worktree or its files yourself; the operator removes it after reading your answer.`)
	return b.String()
}

var verdictRE = regexp.MustCompile(`(?m)^[\s>*` + "`" + `-]*WORKTREE-VERDICT:\s*(pr|removable|keep)\b[ \t]*(.*)$`)

// ParseVerdict returns the last WORKTREE-VERDICT line's verdict and detail.
func ParseVerdict(text string) (verdict, detail string) {
	m := verdictRE.FindAllStringSubmatch(text, -1)
	if len(m) == 0 {
		return "", ""
	}
	last := m[len(m)-1]
	return last[1], strings.TrimSpace(strings.Trim(last[2], "`*"))
}

// reply extracts the agent's final text (and, for Claude Code, the cost).
func reply(harness, stdout, lastFile string) (string, float64) {
	if harness == "claude" {
		var r struct {
			Result       string  `json:"result"`
			TotalCostUSD float64 `json:"total_cost_usd"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &r); err == nil && r.Result != "" {
			return r.Result, r.TotalCostUSD
		}
		return stdout, 0
	}
	if lastFile != "" {
		if b, err := os.ReadFile(lastFile); err == nil && len(bytes.TrimSpace(b)) > 0 {
			return string(b), 0
		}
	}
	return stdout, 0
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// limitedBuffer keeps the first maxOutput bytes of a reply.
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

// Wait blocks until the running ask finishes (tests, shutdown).
func (a *Asker) Wait() { a.wg.Wait() }
