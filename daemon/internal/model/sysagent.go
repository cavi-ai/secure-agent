package model

import "time"

// SysAgentMessage is one turn of the system agent chat (the console's Agent
// tab). Content is stored masked: a secret never reaches the table or the
// model.
type SysAgentMessage struct {
	ID      int64     `json:"id"`
	TS      time.Time `json:"ts"`
	Role    string    `json:"role"` // user | assistant | note
	Content string    `json:"content"`
	// Analysis replies are review-queue items. They remain available after
	// clearing chat; approval still uses the exact stored command by ID.
	Origin      string   `json:"origin,omitempty"` // analysis | worktree | ordinary chat
	FlagIDs     []string `json:"flag_ids,omitempty"`
	ReviewState string   `json:"review_state,omitempty"` // pending | saved | dismissed
	// Harness is retained for older stored messages; new chat never routes to
	// one. Workdir is the folder for a possible local command.
	Harness string `json:"harness,omitempty"`
	Workdir string `json:"workdir,omitempty"`
	// Skills the reply was written with (assistant).
	Skills []string `json:"skills,omitempty"`
	// Usage comes from the local model response. Rates are present only when
	// the server supplies separate prompt and generation durations.
	Usage *SysAgentUsage `json:"usage,omitempty"`
	// Proposal is work the reply hands to a harness (assistant).
	Proposal *SysAgentProposal `json:"proposal,omitempty"`
	// LocalCommand is an exact shell command proposed by the local model.
	// It cannot run until the operator confirms this message's id.
	LocalCommand *SysAgentLocalCommand `json:"local_command,omitempty"`
	LocalRunID   int64                 `json:"local_run_id,omitempty"`
	// PlanID is the plan saved from Proposal, 0 until one is.
	PlanID int64 `json:"plan_id,omitempty"`
}

type SysAgentUsage struct {
	Model                 string  `json:"model"`
	PromptTokens          int     `json:"prompt_tokens,omitempty"`
	CompletionTokens      int     `json:"completion_tokens,omitempty"`
	ElapsedMS             int64   `json:"elapsed_ms"`
	PromptTokensPerSecond float64 `json:"prompt_tokens_per_second,omitempty"`
	OutputTokensPerSecond float64 `json:"output_tokens_per_second,omitempty"`
	ToolCalls             int     `json:"tool_calls"`
}

// SysAgentLocalCommand is a proposed local action, never a harness route.
// Mode is headless or terminal; terminal is required for interactive input.
type SysAgentLocalCommand struct {
	Command string `json:"command"`
	Workdir string `json:"workdir"`
	Mode    string `json:"mode"`
}

// SysAgentProposal is a legacy stored harness proposal. New chat replies
// propose local commands; existing proposals remain dispatchable.
type SysAgentProposal struct {
	Title   string `json:"title"`
	Harness string `json:"harness"` // claude | codex | openclaw | hermes
	Mode    string `json:"mode"`    // headless | terminal
	Workdir string `json:"workdir"`
	// Task is the instruction the harness receives.
	Task string `json:"task"`
	// Steps are what the harness should do, for the operator to read.
	Steps  []string `json:"steps"`
	Skills []string `json:"skills"`
}

// SysAgentPlan is a proposal saved for dispatch now or later.
type SysAgentPlan struct {
	ID        int64     `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	// Source is agent (from a reply) or operator (written in the composer).
	Source    string   `json:"source"`
	MessageID int64    `json:"message_id,omitempty"`
	Title     string   `json:"title"`
	Harness   string   `json:"harness"`
	Mode      string   `json:"mode"`
	Workdir   string   `json:"workdir"`
	Task      string   `json:"task"`
	Steps     []string `json:"steps"`
	Skills    []string `json:"skills"`
	// Model the harness runs; "" = system_agent.harness_model.
	Model string `json:"model,omitempty"`
	// Status is saved, running, opened (a terminal was opened), manual (the
	// command was handed to the operator), done or failed.
	Status string `json:"status"`
	RunID  int64  `json:"run_id,omitempty"`
	// Note says why the plan was saved instead of dispatched.
	Note string `json:"note,omitempty"`
	// Ready and Reason are computed on read: whether the harness can be
	// dispatched now, and why not.
	Ready  bool   `json:"ready"`
	Reason string `json:"reason,omitempty"`
}

// SysAgentRun is one dispatch of a plan to a harness.
type SysAgentRun struct {
	ID         int64      `json:"id"`
	PlanID     int64      `json:"plan_id"`
	TS         time.Time  `json:"ts"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Title      string     `json:"title"`
	Harness    string     `json:"harness"`
	Mode       string     `json:"mode"`
	Model      string     `json:"model"`
	Workdir    string     `json:"workdir"`
	// Status is running, done, failed or timeout (headless), opened or
	// manual (terminal).
	Status   string `json:"status"`
	ExitCode int    `json:"exit_code"`
	// Command is the shell form of what runs: environment, binary and
	// arguments, with the task shown by reference.
	Command string `json:"command"`
	// Output is the masked tail of what a headless run printed.
	Output string `json:"output,omitempty"`
	Detail string `json:"detail,omitempty"`
}
