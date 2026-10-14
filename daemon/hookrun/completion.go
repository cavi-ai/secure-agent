package hookrun

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"
)

// Completion is the host forwarding envelope for one observed handler
// invocation. Result and Before are transient native values, never records.
// It is a Secure Agent transport contract, not a harness event protocol.
type Completion struct {
	Type       string          `json:"type"`
	Version    int             `json:"version"`
	Harness    string          `json:"harness"`
	ID         string          `json:"id"`
	SessionID  string          `json:"session_id"`
	TS         time.Time       `json:"ts"`
	Event      string          `json:"event"`
	Script     string          `json:"script,omitempty"`
	State      string          `json:"state"`
	DurationMs int64           `json:"duration_ms"`
	Protocol   string          `json:"protocol,omitempty"`
	Before     json.RawMessage `json:"before,omitempty"`
	Result     json.RawMessage `json:"result,omitempty"`
	Evidence   *Evidence       `json:"evidence,omitempty"`
}

// DecodeCompletion recognizes only per-handler completions for the selected
// adapter. The host owns timestamps, duration, session identity and retry IDs.
func DecodeCompletion(line []byte, harness string) (Completion, Record, bool, error) {
	var head struct {
		Type       string `json:"type"`
		DurationMs *int64 `json:"duration_ms"`
	}
	if json.Unmarshal(line, &head) != nil {
		return Completion{}, Record{}, false, errors.New("invalid hook completion JSON")
	}
	if head.Type != "hook_completed" {
		return Completion{}, Record{}, false, nil
	}
	var c Completion
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || (c.Version != 1 && c.Version != 2) || c.Harness != harness || (c.Version == 2 && c.Evidence == nil) || (c.Version == 1 && c.Evidence != nil) {
		return Completion{}, Record{}, true, errors.New("invalid hook completion envelope or harness")
	}
	id, err := ExecutionID(harness, c.ID)
	if err != nil {
		return Completion{}, Record{}, true, err
	}
	evidence := c.Evidence
	if evidence == nil {
		evidence = &Evidence{}
	}
	evidence.DurationKnown = head.DurationMs != nil
	r := Record{Type: "hook_run", Version: 2, Harness: harness, ID: id, SessionID: c.SessionID,
		TS: c.TS, Event: c.Event, Script: c.Script, DurationMs: c.DurationMs, Evidence: evidence}
	switch c.State {
	case "completed":
		r.Status = "ok"
	case "error":
		r.Status = "error"
	case "cancelled":
		r.Status = "cancelled"
	default:
		return Completion{}, Record{}, true, errors.New("invalid hook completion state")
	}
	if err := r.Validate(); err != nil {
		return Completion{}, Record{}, true, err
	}
	return c, r, true, nil
}
