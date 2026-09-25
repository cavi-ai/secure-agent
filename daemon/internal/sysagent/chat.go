package sysagent

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// ChatInput is one operator message and what the composer had picked.
type ChatInput struct {
	Message string `json:"message"`
	Harness string `json:"harness"`
	Workdir string `json:"workdir"`
}

// Send stores the operator's message (masked) and starts the reply; the
// reply lands in the store. One reply at a time.
func (a *Agent) Send(in ChatInput) (model.SysAgentMessage, error) {
	cfg := a.config()
	if !cfg.Enabled {
		return model.SysAgentMessage{}, ErrDisabled
	}
	text := strings.TrimSpace(in.Message)
	if text == "" || len(text) > maxMessageLen {
		return model.SysAgentMessage{}, fmt.Errorf("%w: the message must be 1-%d characters", ErrInvalid, maxMessageLen)
	}
	if !a.maskAll(&text) {
		return model.SysAgentMessage{}, ErrSecret
	}
	a.mu.Lock()
	if a.chatting {
		a.mu.Unlock()
		return model.SysAgentMessage{}, fmt.Errorf("%w: the agent is still answering the previous message", ErrBusy)
	}
	a.chatting = true
	a.wg.Add(1)
	a.mu.Unlock()
	m := model.SysAgentMessage{TS: a.now(), Role: "user", Content: text,
		Harness: knownHarness(in.Harness), Workdir: cleanWorkdir(in.Workdir, "")}
	m.ID = a.st.PutSysAgentMessage(m)
	go a.reply(cfg, m)
	return m, nil
}

// note records a message from the daemon itself (not the model).
func (a *Agent) note(text string) {
	a.st.PutSysAgentMessage(model.SysAgentMessage{TS: a.now(), Role: "note", Content: text})
}

const keptHint = " Your message is kept: Save as plan hands it to a harness to run later."

// reply asks the model and records its answer. A proposal whose harness
// cannot run now is saved as a plan with the reason.
func (a *Agent) reply(cfg config.SystemAgentConfig, user model.SysAgentMessage) {
	defer func() {
		a.mu.Lock()
		a.chatting = false
		a.mu.Unlock()
		a.wg.Done()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), chatTimeout)
	defer cancel()
	info := probe(ctx, a.client, cfg.Endpoint)
	if reason := a.agentReason(cfg, info); reason != "" {
		a.note("The local model cannot answer: " + reason + "." + keptHint)
		return
	}
	modelName, _ := chatModel(cfg, info)
	history := a.st.SysAgentMessages(historyLen)
	picked := selectSkills(recentUserText(history, 3)+" "+user.Harness, promptSkills)
	msgs := []chatMessage{{Role: "system", Content: a.systemPrompt(cfg, info, user, picked)}}
	for _, h := range history {
		switch h.Role {
		case "user":
			msgs = append(msgs, chatMessage{Role: "user", Content: h.Content})
		case "assistant":
			msgs = append(msgs, chatMessage{Role: "assistant", Content: withProposalBlock(h)})
		}
	}
	answer, err := chat(ctx, a.client, cfg.Endpoint, modelName, msgs)
	if err != nil {
		a.note("The local model did not answer: " + err.Error() + "." + keptHint)
		return
	}
	ids := []string{}
	for _, s := range picked {
		ids = append(ids, s.ID)
	}
	text, pr := parseReply(answer, user, a.home)
	if !a.maskAll(&text) {
		text, pr = "[reply withheld: it held a secret that could not be masked]", nil
	}
	if pr != nil {
		pr.Skills = knownSkills(append(pr.Skills, ids...))
		ptrs := []*string{&pr.Title, &pr.Task}
		for i := range pr.Steps {
			ptrs = append(ptrs, &pr.Steps[i])
		}
		if !a.maskAll(ptrs...) {
			pr = nil
		}
	}
	if text == "" && pr != nil {
		text = "Proposed: " + pr.Title
	}
	m := model.SysAgentMessage{TS: a.now(), Role: "assistant", Content: text, Skills: ids, Proposal: pr}
	m.ID = a.st.PutSysAgentMessage(m)
	if pr == nil {
		return
	}
	h, _ := harnessByID(pr.Harness)
	if reason := a.harnessReason(cfg, info, h, harnessModel(cfg, info, "")); reason != "" {
		if p, err := a.SavePlan(PlanInput{MessageID: m.ID}); err == nil {
			p.Note = reason
			a.st.PutSysAgentPlan(p)
		}
	}
}

// recentUserText joins the newest n user messages (skill selection looks
// at what the operator has been asking about, not only the last line).
func recentUserText(history []model.SysAgentMessage, n int) string {
	var parts []string
	for i := len(history) - 1; i >= 0 && len(parts) < n; i-- {
		if history[i].Role == "user" {
			parts = append(parts, history[i].Content)
		}
	}
	return strings.Join(parts, "\n")
}

// withProposalBlock renders an assistant message as the model wrote it,
// its proposal back in a dispatch block, so the history teaches the format.
func withProposalBlock(m model.SysAgentMessage) string {
	if m.Proposal == nil {
		return m.Content
	}
	b, _ := json.Marshal(m.Proposal)
	return m.Content + "\n```dispatch\n" + string(b) + "\n```"
}

const systemPreamble = `You are the system agent of secure-agent on the operator's own machine. You run on a local model, so harness changes and sensitive work (SSH keys, Git credentials, commit signing, coding-agent sign-in and config) stay on this machine.

You never run anything yourself. You answer questions, and when the operator wants something done you write a task for a coding agent (a "harness") that also runs on this machine's local model. The operator reviews the task and dispatches it.

To hand work to a harness, end your reply with exactly one block:
` + "```dispatch" + `
{"title":"short title","harness":"<id>","mode":"headless|terminal","workdir":"/absolute/folder","task":"complete instructions for the harness","steps":["step","step"],"skills":["ids of the skills used"]}
` + "```" + `
- mode "terminal" when the work needs the operator at the keyboard: passphrases, browser or device-code logins, hardware keys, or approving each command. Otherwise "headless": the harness edits files inside the folder and cannot run other commands.
- task must stand alone: the harness does not see this chat. Name the files, commands and checks.
- No block for questions and explanations, or when you are unsure: ask instead of guessing.

Rules:
- Never ask for, repeat or write secret values (passwords, tokens, private keys, passphrases). They appear masked as [REDACTED:<rule>]. A command that needs a secret must prompt for it in the terminal.
- Never propose disabling secure-agent, its hooks, guard or firewall, bypassing a harness's approvals or sandbox, or sending keys off this machine.
- Follow the skills below; they are this machine's procedures.
`

// systemPrompt tells the model what it is, the reply format, the state of
// each harness, and the skills this request touches.
func (a *Agent) systemPrompt(cfg config.SystemAgentConfig, info ollamaInfo, user model.SysAgentMessage, picked []Skill) string {
	var b strings.Builder
	b.WriteString(systemPreamble)
	hm := harnessModel(cfg, info, "")
	b.WriteString("\nHarnesses (id: state):\n")
	for _, h := range Harnesses {
		state := "ready"
		if reason := a.harnessReason(cfg, info, h, hm); reason != "" {
			state = "not available now (" + reason + "); a proposal is saved as a plan to dispatch later"
		}
		fmt.Fprintf(&b, "- %s (%s): %s\n", h.ID, h.Label, state)
	}
	if user.Harness != "" {
		fmt.Fprintf(&b, "The operator routes this request to harness %q.\n", user.Harness)
	}
	fmt.Fprintf(&b, "Folder: %s\n", cleanWorkdir(user.Workdir, a.home))
	b.WriteString("\nSkills (id: what it covers):\n")
	for _, s := range skills {
		fmt.Fprintf(&b, "- %s: %s\n", s.ID, s.Summary)
	}
	for _, s := range picked {
		fmt.Fprintf(&b, "\n<skill id=%q>\n%s\n</skill>\n", s.ID, s.Body)
	}
	return b.String()
}

var dispatchRE = regexp.MustCompile("(?s)```[ \\t]*dispatch[ \\t]*\\n(.*?)```")

// parseReply splits the model's answer into prose and the last dispatch
// block's proposal. A block that is not a JSON object with a task leaves
// the answer as prose. The operator's harness pick wins over the model's;
// the model's folder is kept only when absolute.
func parseReply(answer string, user model.SysAgentMessage, home string) (string, *model.SysAgentProposal) {
	matches := dispatchRE.FindAllStringSubmatch(answer, -1)
	if len(matches) == 0 {
		return strings.TrimSpace(answer), nil
	}
	raw := strings.TrimSpace(matches[len(matches)-1][1])
	if i, j := strings.IndexByte(raw, '{'), strings.LastIndexByte(raw, '}'); i >= 0 && j > i {
		raw = raw[i : j+1]
	}
	var in struct {
		Title, Harness, Mode, Workdir, Task string
		Steps, Skills                       []string
	}
	if json.Unmarshal([]byte(raw), &in) != nil || strings.TrimSpace(in.Task) == "" {
		return strings.TrimSpace(answer), nil
	}
	pr := &model.SysAgentProposal{
		Title:   clip(in.Title, maxTitleLen),
		Harness: user.Harness,
		Mode:    in.Mode,
		Workdir: cleanWorkdir(in.Workdir, cleanWorkdir(user.Workdir, home)),
		Task:    clip(in.Task, maxTaskLen),
		Steps:   []string{},
		Skills:  knownSkills(in.Skills),
	}
	if pr.Harness == "" {
		pr.Harness = knownHarness(in.Harness)
	}
	if pr.Harness == "" {
		pr.Harness = Harnesses[0].ID
	}
	if pr.Mode != ModeHeadless {
		pr.Mode = ModeTerminal // the operator at the keyboard is the safe default
	}
	if pr.Title == "" {
		pr.Title = clip(strings.SplitN(pr.Task, "\n", 2)[0], 80)
	}
	for _, s := range in.Steps {
		if s = clip(s, maxStepLen); s != "" && len(pr.Steps) < maxSteps {
			pr.Steps = append(pr.Steps, s)
		}
	}
	return strings.TrimSpace(dispatchRE.ReplaceAllString(answer, "")), pr
}
