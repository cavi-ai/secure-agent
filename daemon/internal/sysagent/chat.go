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

// ChatInput is one operator message and the folder for a possible local action.
// Harness is retained only to reject older clients that ambiguously routed chat.
type ChatInput struct {
	Message string `json:"message"`
	Harness string `json:"harness"`
	Workdir string `json:"workdir"`
}

// Send stores the operator's message (masked) and starts the reply; the
// reply lands in the store. One reply at a time.
func (a *Agent) Send(in ChatInput) (model.SysAgentMessage, error) {
	return a.send(in, "", nil)
}

// SendAnalysis uses the same local, masked Ollama path as ordinary chat.
// The caller supplies a daemon-built evidence summary, never browser text.
func (a *Agent) SendAnalysis(prompt string, flagIDs []string) (model.SysAgentMessage, error) {
	if a.st.PendingSysAgentRecommendations() >= 100 {
		return model.SysAgentMessage{}, fmt.Errorf("%w: review pending recommendations before starting another analysis", ErrBusy)
	}
	return a.send(ChatInput{Message: prompt, Workdir: a.home}, "analysis", flagIDs)
}

func (a *Agent) send(in ChatInput, origin string, flagIDs []string) (model.SysAgentMessage, error) {
	cfg := a.config()
	if !cfg.Enabled {
		return model.SysAgentMessage{}, ErrDisabled
	}
	text := strings.TrimSpace(in.Message)
	if text == "" || len(text) > maxMessageLen {
		return model.SysAgentMessage{}, fmt.Errorf("%w: the message must be 1-%d characters", ErrInvalid, maxMessageLen)
	}
	if in.Harness != "" {
		return model.SysAgentMessage{}, fmt.Errorf("%w: chat stays on local Ollama; save a harness plan in the Harness handoff section", ErrInvalid)
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
		Workdir: cleanWorkdir(in.Workdir, ""), Origin: origin, FlagIDs: flagIDs}
	m.ID = a.st.PutSysAgentMessage(m)
	go a.reply(cfg, m)
	return m, nil
}

// note records a message from the daemon itself (not the model).
func (a *Agent) note(text string) {
	a.st.PutSysAgentMessage(model.SysAgentMessage{TS: a.now(), Role: "note", Content: text})
}

const keptHint = " Your message is kept. Harness handoff is available separately."

// reply asks the local model and records its answer and optional command
// proposal. A reply never starts a command or creates a harness plan.
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
	if user.Origin == "analysis" {
		// Each scan is grounded only in its daemon-built snapshot; an earlier
		// recommendation must not steer a fresh security assessment.
		history = []model.SysAgentMessage{user}
	} else {
		plain := history[:0]
		for _, h := range history {
			if h.Origin != "analysis" {
				plain = append(plain, h)
			}
		}
		history = plain
	}
	picked := selectSkills(recentUserText(history, 3), promptSkills)
	msgs := []chatMessage{{Role: "system", Content: a.systemPrompt(user, picked)}}
	for _, h := range history {
		switch h.Role {
		case "user":
			msgs = append(msgs, chatMessage{Role: "user", Content: h.Content})
		case "assistant":
			msgs = append(msgs, chatMessage{Role: "assistant", Content: h.Content})
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
	text, local := parseLocalCommand(answer, user, a.home)
	if !a.maskAll(&text) {
		text, local = "[reply withheld: it held a secret that could not be masked]", nil
	}
	if local != nil && !a.maskAll(&local.Command) {
		local = nil
	}
	if text == "" && local != nil {
		text = "I can run this local command after you review and confirm it."
	}
	m := model.SysAgentMessage{TS: a.now(), Role: "assistant", Content: text, Skills: ids, LocalCommand: local,
		Origin: user.Origin, FlagIDs: user.FlagIDs}
	if user.Origin == "analysis" {
		m.ReviewState = "pending"
	}
	m.ID = a.st.PutSysAgentMessage(m)
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

const systemPreamble = `You are the system agent of secure-agent on the operator's own machine. You answer through local Ollama. You do not call other coding agents during chat.

When the operator asks you to do local work, propose one exact shell command for review. The daemon runs it only after the operator separately confirms it. Prefer a short, inspectable command. Use terminal mode for passphrases, hardware keys, login, or any interactive command. Do not include secret values in commands. When creating an SSH key, let ssh-keygen prompt for its passphrase in terminal mode.

To propose a local command, end your reply with exactly one block:
` + "```local-command" + `
{"command":"exact shell command","mode":"headless|terminal","workdir":"/absolute/folder"}
` + "```" + `
- Use mode "terminal" for interactive work. A headless command has no terminal and a timeout.
- No block for questions, explanations, or uncertain instructions: ask instead of guessing.
- Harness handoff is a separate operator-controlled section. Never emit a dispatch block or claim this chat routed to a harness.

Rules:
- Never ask for, repeat or write secret values (passwords, tokens, private keys, passphrases). They appear masked as [REDACTED:<rule>]. A command that needs a secret must prompt for it in the terminal.
- Never propose disabling secure-agent, its hooks, guard or firewall, or sending keys off this machine.
- Follow the skills below; they are this machine's procedures.
`

// systemPrompt tells the model the local command format and relevant skills.
func (a *Agent) systemPrompt(user model.SysAgentMessage, picked []Skill) string {
	var b strings.Builder
	b.WriteString(systemPreamble)
	fmt.Fprintf(&b, "Local command folder: %s\n", cleanWorkdir(user.Workdir, a.home))
	b.WriteString("\nSkills (id: what it covers):\n")
	for _, s := range skills {
		fmt.Fprintf(&b, "- %s: %s\n", s.ID, s.Summary)
	}
	for _, s := range picked {
		fmt.Fprintf(&b, "\n<skill id=%q>\n%s\n</skill>\n", s.ID, s.Body)
	}
	return b.String()
}

var localCommandRE = regexp.MustCompile("(?s)```[ \\t]*local-command[ \\t]*\\n(.*?)```")

// parseLocalCommand accepts one bounded, typed command proposal. The model
// cannot execute it; the UI must show the exact command before a separate
// API call by message id. Invalid blocks remain visible as ordinary text.
func parseLocalCommand(answer string, user model.SysAgentMessage, home string) (string, *model.SysAgentLocalCommand) {
	matches := localCommandRE.FindAllStringSubmatch(answer, -1)
	if len(matches) != 1 {
		return strings.TrimSpace(answer), nil
	}
	var in model.SysAgentLocalCommand
	if json.Unmarshal([]byte(strings.TrimSpace(matches[0][1])), &in) != nil {
		return strings.TrimSpace(answer), nil
	}
	in.Command = strings.TrimSpace(in.Command)
	if in.Command == "" || len(in.Command) > 2048 || strings.ContainsRune(in.Command, 0) {
		return strings.TrimSpace(answer), nil
	}
	if in.Mode != ModeHeadless && in.Mode != ModeTerminal {
		in.Mode = ModeTerminal
	}
	in.Workdir = cleanWorkdir(in.Workdir, cleanWorkdir(user.Workdir, home))
	return strings.TrimSpace(localCommandRE.ReplaceAllString(answer, "")), &in
}
