package model

import "time"

type Flag struct {
	ID       string    `json:"id"`
	Rule     string    `json:"rule"`
	Severity int       `json:"severity"`
	TS       time.Time `json:"ts"`
	PID      int32     `json:"pid"`
	Agent    string    `json:"agent"`
	// SessionID groups the flag with its harness session, so fleet consumers
	// can follow one agent run end-to-end even after PIDs are recycled.
	SessionID string   `json:"session_id,omitempty"`
	Evidence  []string `json:"evidence"`
	// Advisor carries the local advisor's triage verdict when one exists.
	// Advisory only — never an enforcement input.
	Advisor *AdvisorVerdict `json:"advisor,omitempty"`
}
