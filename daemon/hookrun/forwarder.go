package hookrun

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"
)

// ForwarderReport is an optional host observation, not a hook completion or a
// protection claim. ForwarderID identifies one reporting instance and scope.
// Hosts use a new opaque ID on restart or when changing session scope.
type ForwarderReport struct {
	Type             string    `json:"type"`
	Version          int       `json:"version"`
	Harness          string    `json:"harness"`
	ForwarderID      string    `json:"forwarder_id"`
	Sequence         uint64    `json:"sequence"`
	SessionID        string    `json:"session_id,omitempty"`
	TS               time.Time `json:"ts"`
	State            string    `json:"state"`
	Pending          uint64    `json:"pending"`
	DeliveryFailures uint64    `json:"delivery_failures"`
	Dropped          uint64    `json:"dropped"`
}

func (r ForwarderReport) Validate() error {
	if r.Type != "hook_forwarder" || r.Version != 1 {
		return errors.New("unsupported hook forwarder report version")
	}
	switch r.Harness {
	case "claude", "codex", "openclaw", "hermes", "opencode":
	default:
		return errors.New("unsupported hook forwarder harness")
	}
	if !identifier.MatchString(r.ForwarderID) || (r.SessionID != "" && !identifier.MatchString(r.SessionID)) {
		return errors.New("invalid hook forwarder identity")
	}
	switch r.State {
	case "connected", "disconnected", "error":
	default:
		return errors.New("invalid hook forwarder state")
	}
	const maxSafeInteger = 1<<53 - 1
	if r.Sequence == 0 || r.Sequence > maxSafeInteger || r.Pending > maxSafeInteger || r.DeliveryFailures > maxSafeInteger || r.Dropped > maxSafeInteger || r.TS.IsZero() || r.TS.Year() < 1 || r.TS.Year() > 9999 {
		return errors.New("invalid hook forwarder time or count")
	}
	return nil
}

func DecodeForwarderReport(line []byte) (ForwarderReport, bool, error) {
	var head struct {
		Type string `json:"type"`
	}
	if !bytes.Contains(line, []byte(`"hook_forwarder"`)) || json.Unmarshal(line, &head) != nil || head.Type != "hook_forwarder" {
		return ForwarderReport{}, false, nil
	}
	var r ForwarderReport
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil {
		return ForwarderReport{}, true, errors.New("invalid hook forwarder report")
	}
	var counts struct {
		Pending          *uint64 `json:"pending"`
		DeliveryFailures *uint64 `json:"delivery_failures"`
		Dropped          *uint64 `json:"dropped"`
	}
	if json.Unmarshal(line, &counts) != nil || counts.Pending == nil || counts.DeliveryFailures == nil || counts.Dropped == nil {
		return ForwarderReport{}, true, errors.New("missing hook forwarder counters")
	}
	if err := r.Validate(); err != nil {
		return ForwarderReport{}, true, err
	}
	return r, true, nil
}
