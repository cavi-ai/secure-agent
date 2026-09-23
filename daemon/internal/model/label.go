package model

import "time"

// OperatorLabel is one operator judgment on a finding's subject: ok (routine
// for this agent) or not_ok. Pattern is the file path or host the judgment
// is about; Source names the action that recorded it (mark, allow-host,
// allow-path, mute, guard-allow, guard-deny, kill).
type OperatorLabel struct {
	ID        int64     `json:"id"`
	Kind      string    `json:"kind"` // flag | file | host | guard
	Rule      string    `json:"rule,omitempty"`
	Agent     string    `json:"agent,omitempty"`
	Pattern   string    `json:"pattern,omitempty"`
	Label     string    `json:"label"` // ok | not_ok
	Reason    string    `json:"reason,omitempty"`
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
}

// LabelSummary counts the operator's labels on the same case.
type LabelSummary struct {
	OK    int `json:"ok"`
	NotOK int `json:"not_ok"`
}

// LabelSuggestion is offered after consistent labels: the label they agree
// on, a sentence, and the served action that applies it (empty when none is
// served).
type LabelSuggestion struct {
	Label    string `json:"label"`
	Text     string `json:"text"`
	ActionID string `json:"action_id,omitempty"`
}

// LabelContext is what the operator decided before about cases like this
// one.
type LabelContext struct {
	Summary    LabelSummary     `json:"summary"`
	Similar    []OperatorLabel  `json:"similar"`
	Suggestion *LabelSuggestion `json:"suggestion,omitempty"`
}
