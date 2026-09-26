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
	// Harness and Workdir: what the composer had picked when the operator
	// wrote a user message.
	Harness string `json:"harness,omitempty"`
	Workdir string `json:"workdir,omitempty"`
	// Skills the reply was written with (assistant).
	Skills []string `json:"skills,omitempty"`
	// Proposal is work the reply hands to a harness (assistant).
	Proposal *SysAgentProposal `json:"proposal,omitempty"`
	// PlanID is the plan saved from Proposal, 0 until one is.
	PlanID int64 `json:"plan_id,omitempty"`
}

// SysAgentProposal is work the system agent proposes for a harness. Nothing
// runs until the operator dispatches it.
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
