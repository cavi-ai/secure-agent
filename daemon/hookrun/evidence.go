package hookrun

import "errors"

// Evidence contains optional facts observed by a forwarding host. Identifiers
// must be opaque inventory/revision/call tokens, never paths, commands or text.
// Absence means unknown. A host-declared role is not proof of enforcement.
type Evidence struct {
	HandlerID     string `json:"handler_id,omitempty"`
	ConfigID      string `json:"config_id,omitempty"`
	OperationID   string `json:"operation_id,omitempty"`
	ExecutionMode string `json:"execution_mode,omitempty"` // foreground | background
	ReasonCode    string `json:"reason_code,omitempty"`
	ControlRole   string `json:"control_role,omitempty"`   // security | other
	ActionOutcome string `json:"action_outcome,omitempty"` // stopped | proceeded
	DurationKnown bool   `json:"duration_known"`
	CharsKnown    bool   `json:"chars_known"`
	// ContextChars counts model context contributed by this handler, excluding
	// decision feedback and diagnostic text. Nil is unknown; zero is measured.
	ContextChars *int64 `json:"context_chars,omitempty"`
}

func (e Evidence) Validate() error {
	for _, id := range []string{e.HandlerID, e.ConfigID, e.OperationID} {
		if id != "" && !identifier.MatchString(id) {
			return errors.New("invalid hook evidence identity")
		}
	}
	if e.ExecutionMode != "" && e.ExecutionMode != "foreground" && e.ExecutionMode != "background" {
		return errors.New("invalid hook execution mode")
	}
	if e.ControlRole != "" && e.ControlRole != "security" && e.ControlRole != "other" {
		return errors.New("invalid hook control role")
	}
	if e.ActionOutcome != "" && e.ActionOutcome != "stopped" && e.ActionOutcome != "proceeded" {
		return errors.New("invalid hook action outcome")
	}
	switch e.ReasonCode {
	case "", "timeout", "dependency-unavailable", "invalid-output", "permission-denied", "execution-failed", "policy-block":
	default:
		return errors.New("invalid hook reason code")
	}
	if e.ContextChars != nil && *e.ContextChars < 0 {
		return errors.New("invalid hook context count")
	}
	return nil
}
