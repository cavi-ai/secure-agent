// Package sysagent is the system agent behind the console's Agent tab: a
// chat with a model served by a LOCAL Ollama that answers questions, drafts
// work for a coding agent ("harness": Claude Code, Codex, OpenClaw, Hermes
// Agent) and saves it as a plan the operator dispatches — headless in a
// folder, or in a terminal the operator drives. Dispatched harnesses run
// against the same Ollama, so sensitive work (keys, sign-in, signing,
// harness config) never reaches a vendor model.
//
// Invariants (docs/SYSTEM_AGENT.md):
//   - Loopback only: the endpoint is validated in config and again here;
//     every harness recipe points the harness at it.
//   - The model proposes, the operator disposes: a reply can only carry a
//     proposal. Nothing runs until the operator dispatches a plan, and a
//     plan never dispatches itself.
//   - Secrets never persist or reach the model: each message is masked by
//     the firewall's detectors and fingerprints first, and a message whose
//     secret survives masking is refused.
//   - Harnesses keep their own permission model: no recipe bypasses
//     approvals or the sandbox, and the operator's hooks stay on.
//   - One headless run at a time, bounded by a timeout, in its own process
//     group.
package sysagent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/toolpath"
)

var (
	// ErrDisabled: system_agent.enabled is false.
	ErrDisabled = errors.New("the system agent is off: set system_agent.enabled: true in ~/.config/secure-agent/config.yaml")
	// ErrBusy: the chat is answering, or a headless run is in flight.
	ErrBusy = errors.New("busy")
	// ErrNotFound: no plan with that id.
	ErrNotFound = errors.New("no such plan")
	// ErrSecret: the text holds a secret masking cannot remove.
	ErrSecret = errors.New("the text holds a secret that cannot be masked (it may be encoded); remove it and describe what it is instead")
	// ErrInvalid: a request field is missing or malformed.
	ErrInvalid = errors.New("invalid request")
	// ErrUnavailable: the harness cannot run now; the plan stays saved.
	ErrUnavailable = errors.New("not available now")
)

// Store is what the agent reads and records. *store.Store satisfies it.
type Store interface {
	PutSysAgentMessage(model.SysAgentMessage) int64
	GetSysAgentMessage(id int64) (model.SysAgentMessage, bool)
	SysAgentMessages(limit int) []model.SysAgentMessage
	ClearSysAgentMessages()
	PutSysAgentPlan(model.SysAgentPlan) int64
	GetSysAgentPlan(id int64) (model.SysAgentPlan, bool)
	SysAgentPlans(limit int) []model.SysAgentPlan
	DeleteSysAgentPlan(id int64) bool
	PutSysAgentRun(model.SysAgentRun) int64
	SysAgentRuns(limit int) []model.SysAgentRun
	PutAudit(store.AuditEntry)
}

// Bounds on what the agent takes and keeps.
const (
	maxMessageLen = 8000
	maxTaskLen    = 8000
	maxTitleLen   = 120
	maxSteps      = 10
	maxStepLen    = 300
	historyLen    = 20
	promptSkills  = 3
)

// Agent is the system agent. The zero value is not usable; call New.
type Agent struct {
	st       Store
	mask     func(string) (string, bool)
	stateDir string
	home     string
	binDirs  []string
	look     func(name string) string
	// openTerminal opens a script in a terminal window; nil (or an error)
	// hands the command to the operator instead.
	openTerminal func(script string) error
	now          func() time.Time
	client       *http.Client

	mu       sync.Mutex
	cfg      config.SystemAgentConfig
	chatting bool
	running  int64 // run id of the headless run in flight
	wg       sync.WaitGroup
}

// New builds the agent. stateDir holds pinned harness configs and terminal
// scripts (created 0700 on first use); mask is the firewall's masker (nil
// masks nothing — tests only).
func New(st Store, stateDir string, mask func(string) (string, bool)) *Agent {
	home, _ := os.UserHomeDir()
	a := &Agent{
		st: st, mask: mask, stateDir: stateDir, home: home, binDirs: toolpath.Dirs(home),
		openTerminal: openTerminal, now: time.Now,
		client: &http.Client{Timeout: chatTimeout},
	}
	a.look = func(name string) string { return toolpath.Look(name, a.binDirs) }
	if a.mask == nil {
		a.mask = func(s string) (string, bool) { return s, true }
	}
	return a
}

// SetConfig applies a (hot-reloaded) configuration.
func (a *Agent) SetConfig(cfg config.SystemAgentConfig) {
	a.mu.Lock()
	defer a.mu.Unlock()
	cfg.Endpoint = strings.TrimSuffix(strings.TrimSpace(cfg.Endpoint), "/")
	a.cfg = cfg
}

// config returns the configuration in force; enabled only with a loopback
// endpoint (validated in config too — this is the second layer).
func (a *Agent) config() config.SystemAgentConfig {
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.cfg
	c.Enabled = c.Enabled && advisor.IsLoopbackEndpoint(c.Endpoint)
	return c
}

// HarnessStatus is one harness as the console shows it.
type HarnessStatus struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Bin       string `json:"bin"`
	MinOllama string `json:"min_ollama,omitempty"`
	Path      string `json:"path,omitempty"`
	Installed bool   `json:"installed"`
	Ready     bool   `json:"ready"`
	Reason    string `json:"reason,omitempty"`
}

// SkillInfo is a skill without its body.
type SkillInfo struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Summary string `json:"summary"`
}

// AgentStatus is the agent's state for the console.
type AgentStatus struct {
	Enabled       bool            `json:"enabled"`
	Endpoint      string          `json:"endpoint"`
	Reachable     bool            `json:"reachable"`
	OllamaVersion string          `json:"ollama_version,omitempty"`
	Reason        string          `json:"reason,omitempty"`
	Model         string          `json:"model,omitempty"`
	HarnessModel  string          `json:"harness_model,omitempty"`
	Models        []string        `json:"models"`
	Harnesses     []HarnessStatus `json:"harnesses"`
	Skills        []SkillInfo     `json:"skills"`
	Chatting      bool            `json:"chatting"`
	RunningRun    int64           `json:"running_run,omitempty"`
	// Terminal is true when a dispatch can open a terminal window here;
	// otherwise terminal mode hands the command to the operator.
	Terminal bool   `json:"terminal"`
	Home     string `json:"home"`
}

// Status probes Ollama and every harness.
func (a *Agent) Status(ctx context.Context) AgentStatus {
	cfg := a.config()
	st := AgentStatus{Enabled: cfg.Enabled, Endpoint: cfg.Endpoint, Models: []string{}, Terminal: a.openTerminal != nil, Home: a.home}
	for _, s := range skills {
		st.Skills = append(st.Skills, SkillInfo{ID: s.ID, Title: s.Title, Summary: s.Summary})
	}
	a.mu.Lock()
	st.Chatting, st.RunningRun = a.chatting, a.running
	a.mu.Unlock()
	var info ollamaInfo
	if cfg.Enabled {
		info = probe(ctx, a.client, cfg.Endpoint)
		st.Reachable, st.OllamaVersion, st.Models = info.Reachable, info.Version, info.Models
		st.Model, _ = chatModel(cfg, info)
		st.HarnessModel = harnessModel(cfg, info, "")
	}
	st.Reason = a.agentReason(cfg, info)
	for _, h := range Harnesses {
		hs := HarnessStatus{ID: h.ID, Label: h.Label, Bin: h.Bin, MinOllama: h.MinOllama, Path: a.look(h.Bin)}
		hs.Installed = hs.Path != ""
		hs.Reason = a.harnessReason(cfg, info, h, st.HarnessModel)
		hs.Ready = hs.Reason == ""
		st.Harnesses = append(st.Harnesses, hs)
	}
	return st
}

// agentReason says why the chat cannot answer; "" when it can.
func (a *Agent) agentReason(cfg config.SystemAgentConfig, info ollamaInfo) string {
	if !cfg.Enabled {
		return ErrDisabled.Error()
	}
	if !info.Reachable {
		return fmt.Sprintf("Ollama is not answering at %s (%s): start it with ollama serve", cfg.Endpoint, info.Err)
	}
	if _, err := chatModel(cfg, info); err != nil {
		return err.Error()
	}
	return ""
}

// harnessReason says why h cannot be dispatched with modelName; "" when it
// can.
func (a *Agent) harnessReason(cfg config.SystemAgentConfig, info ollamaInfo, h Harness, modelName string) string {
	switch {
	case !cfg.Enabled:
		return ErrDisabled.Error()
	case a.look(h.Bin) == "":
		return fmt.Sprintf("%s is not installed where the daemon can find it (%s)", h.Label, h.Bin)
	case !info.Reachable:
		return fmt.Sprintf("Ollama is not answering at %s", cfg.Endpoint)
	case !versionAtLeast(info.Version, h.MinOllama):
		return fmt.Sprintf("%s needs Ollama %s or newer; this one is %s", h.Label, h.MinOllama, info.Version)
	case modelName == "":
		return "Ollama has no model pulled: ollama pull <model>"
	case !info.hasModel(modelName):
		return fmt.Sprintf("model %s is not pulled: ollama pull %s", modelName, modelName)
	}
	return ""
}

// chatModel is the configured chat model, else the first one pulled.
func chatModel(cfg config.SystemAgentConfig, info ollamaInfo) (string, error) {
	if cfg.Model != "" {
		if info.Reachable && !info.hasModel(cfg.Model) {
			return cfg.Model, fmt.Errorf("model %s is not pulled: ollama pull %s", cfg.Model, cfg.Model)
		}
		return cfg.Model, nil
	}
	if len(info.Models) == 0 {
		return "", errors.New("Ollama has no model pulled: ollama pull <model>")
	}
	return info.Models[0], nil
}

// harnessModel is the plan's model, else harness_model, else the chat
// model.
func harnessModel(cfg config.SystemAgentConfig, info ollamaInfo, planModel string) string {
	switch {
	case planModel != "":
		return planModel
	case cfg.HarnessModel != "":
		return cfg.HarnessModel
	}
	m, _ := chatModel(cfg, info)
	return m
}

// Wait blocks until the chat reply and headless run in flight finish
// (tests, shutdown).
func (a *Agent) Wait() { a.wg.Wait() }

// Messages returns the newest limit chat messages, oldest first.
func (a *Agent) Messages(limit int) []model.SysAgentMessage { return a.st.SysAgentMessages(limit) }

// Runs returns dispatches newest first.
func (a *Agent) Runs(limit int) []model.SysAgentRun { return a.st.SysAgentRuns(limit) }

// Clear deletes the chat; plans and runs stay.
func (a *Agent) Clear() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.chatting {
		return fmt.Errorf("%w: the agent is answering", ErrBusy)
	}
	a.st.ClearSysAgentMessages()
	return nil
}

// cleanWorkdir returns dir cleaned when absolute, else fallback.
func cleanWorkdir(dir, fallback string) string {
	if dir = strings.TrimSpace(dir); dir != "" && filepath.IsAbs(dir) {
		return filepath.Clean(dir)
	}
	return fallback
}

// clip trims s and cuts it to n bytes on a rune boundary.
func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	for n > 0 && !isRuneStart(s[n]) {
		n--
	}
	return strings.TrimSpace(s[:n]) + "…"
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

// maskAll masks every string; false when any keeps a secret.
func (a *Agent) maskAll(ss ...*string) bool {
	for _, s := range ss {
		m, clean := a.mask(*s)
		if !clean {
			return false
		}
		*s = m
	}
	return true
}

// PlanInput is a plan written or edited by the operator.
type PlanInput struct {
	ID        int64    `json:"id"`
	MessageID int64    `json:"message_id"`
	Title     string   `json:"title"`
	Harness   string   `json:"harness"`
	Mode      string   `json:"mode"`
	Workdir   string   `json:"workdir"`
	Task      string   `json:"task"`
	Steps     []string `json:"steps"`
	Skills    []string `json:"skills"`
	Model     string   `json:"model"`
}

// SavePlan creates a plan, or edits plan in.ID. A plan from a reply
// (MessageID) starts from the reply's proposal: fields in fill in over it.
func (a *Agent) SavePlan(in PlanInput) (model.SysAgentPlan, error) {
	p := model.SysAgentPlan{CreatedAt: a.now(), Source: "operator", Status: "saved"}
	switch {
	case in.ID != 0:
		old, ok := a.st.GetSysAgentPlan(in.ID)
		if !ok {
			return p, ErrNotFound
		}
		if a.planRunning(old) {
			return p, fmt.Errorf("%w: plan %d is running", ErrBusy, in.ID)
		}
		p = old
	case in.MessageID != 0:
		m, ok := a.st.GetSysAgentMessage(in.MessageID)
		if !ok || m.Proposal == nil {
			return p, fmt.Errorf("%w: message %d carries no proposal", ErrInvalid, in.MessageID)
		}
		if m.PlanID != 0 {
			if old, ok := a.st.GetSysAgentPlan(m.PlanID); ok {
				p = old
				break
			}
		}
		pr := m.Proposal
		p.Source, p.MessageID = "agent", m.ID
		p.Title, p.Harness, p.Mode, p.Workdir, p.Task = pr.Title, pr.Harness, pr.Mode, pr.Workdir, pr.Task
		p.Steps, p.Skills = pr.Steps, pr.Skills
	}
	if in.Title != "" {
		p.Title = in.Title
	}
	if in.Harness != "" {
		p.Harness = in.Harness
	}
	if in.Mode != "" {
		p.Mode = in.Mode
	}
	if in.Workdir != "" {
		p.Workdir = in.Workdir
	}
	if in.Task != "" {
		p.Task = in.Task
	}
	if in.Steps != nil {
		p.Steps = in.Steps
	}
	if in.Skills != nil {
		p.Skills = in.Skills
	}
	if in.Model != "" {
		p.Model = in.Model
	}
	if err := a.normalizePlan(&p); err != nil {
		return p, err
	}
	p.ID = a.st.PutSysAgentPlan(p)
	if p.MessageID != 0 {
		if m, ok := a.st.GetSysAgentMessage(p.MessageID); ok && m.PlanID != p.ID {
			m.PlanID = p.ID
			a.st.PutSysAgentMessage(m)
		}
	}
	return p, nil
}

// normalizePlan validates and bounds a plan in place, masking its text.
func (a *Agent) normalizePlan(p *model.SysAgentPlan) error {
	if _, ok := harnessByID(p.Harness); !ok {
		return fmt.Errorf("%w: harness must be one of claude, codex, openclaw, hermes", ErrInvalid)
	}
	if p.Mode != ModeHeadless && p.Mode != ModeTerminal {
		return fmt.Errorf("%w: mode must be headless or terminal", ErrInvalid)
	}
	p.Workdir = cleanWorkdir(p.Workdir, "")
	if p.Workdir == "" {
		return fmt.Errorf("%w: the folder must be an absolute path", ErrInvalid)
	}
	p.Task = strings.TrimSpace(p.Task)
	if p.Task == "" || len(p.Task) > maxTaskLen {
		return fmt.Errorf("%w: the task must be 1-%d characters", ErrInvalid, maxTaskLen)
	}
	p.Title = clip(p.Title, maxTitleLen)
	if p.Title == "" {
		p.Title = clip(strings.SplitN(p.Task, "\n", 2)[0], 80)
	}
	steps := []string{}
	for _, s := range p.Steps {
		if s = clip(s, maxStepLen); s != "" && len(steps) < maxSteps {
			steps = append(steps, s)
		}
	}
	p.Steps = steps
	p.Skills = knownSkills(p.Skills)
	p.Model = strings.TrimSpace(p.Model)
	ptrs := []*string{&p.Title, &p.Task}
	for i := range p.Steps {
		ptrs = append(ptrs, &p.Steps[i])
	}
	if !a.maskAll(ptrs...) {
		return ErrSecret
	}
	return nil
}

// Plans returns plans newest first, each with whether it can be
// dispatched now.
func (a *Agent) Plans(ctx context.Context, limit int) []model.SysAgentPlan {
	plans := a.st.SysAgentPlans(limit)
	if len(plans) == 0 {
		return plans
	}
	cfg := a.config()
	var info ollamaInfo
	if cfg.Enabled {
		info = probe(ctx, a.client, cfg.Endpoint)
	}
	for i := range plans {
		h, _ := harnessByID(plans[i].Harness)
		plans[i].Reason = a.harnessReason(cfg, info, h, harnessModel(cfg, info, plans[i].Model))
		plans[i].Ready = plans[i].Reason == ""
	}
	return plans
}

// DeletePlan deletes a plan that is not running.
func (a *Agent) DeletePlan(id int64) error {
	p, ok := a.st.GetSysAgentPlan(id)
	if !ok {
		return ErrNotFound
	}
	if a.planRunning(p) {
		return fmt.Errorf("%w: plan %d is running", ErrBusy, id)
	}
	a.st.DeleteSysAgentPlan(id)
	a.st.PutAudit(store.AuditEntry{Action: "sysagent-plan-delete", Detail: fmt.Sprintf("plan=%d harness=%s", id, p.Harness)})
	return nil
}

// knownHarness returns id when it names a harness, else "".
func knownHarness(id string) string {
	if _, ok := harnessByID(id); ok {
		return id
	}
	return ""
}

// planRunning reports whether p's headless run is in flight in this
// process (a "running" status left by a stopped daemon is not).
func (a *Agent) planRunning(p model.SysAgentPlan) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return p.Status == "running" && a.running != 0 && a.running == p.RunID
}

// Recover closes runs and plans a stopped daemon left "running": their
// outcome was never recorded. Call once at start, before serving.
func (a *Agent) Recover() {
	fin := a.now()
	for _, r := range a.st.SysAgentRuns(1000) {
		if r.Status == "running" {
			r.Status, r.FinishedAt, r.Detail = "failed", &fin, "the daemon stopped during the run; its outcome was not recorded"
			a.st.PutSysAgentRun(r)
		}
	}
	for _, p := range a.st.SysAgentPlans(1000) {
		if p.Status == "running" {
			p.Status = "failed"
			a.st.PutSysAgentPlan(p)
		}
	}
}

// Chatting reports whether a reply is being written.
func (a *Agent) Chatting() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.chatting
}
