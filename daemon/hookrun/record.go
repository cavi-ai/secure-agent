// Package hookrun defines the metadata contract shared by harness adapters.
package hookrun

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"time"
)

// Record contains only completion metadata. Adapters must not copy arguments,
// source paths, or hook output into it. ID identifies an execution, not a handler.
type Record struct {
	Type       string    `json:"type"`
	Version    int       `json:"version"`
	Harness    string    `json:"harness"`
	SessionID  string    `json:"session_id"`
	ID         string    `json:"run_id"`
	TS         time.Time `json:"ts"`
	Event      string    `json:"event"`
	Script     string    `json:"script,omitempty"`
	Status     string    `json:"status"`
	DurationMs int64     `json:"duration_ms"`
	Chars      int64     `json:"chars"`
	Evidence   *Evidence `json:"evidence,omitempty"`
}

// Decoder converts one host event into a completed hook record. Unrelated
// messages return ok=false; recognized but invalid messages return an error.
type Decoder interface {
	Decode([]byte) (Record, bool, error)
}

// RecordDecoder accepts the common contract for hosts that normalize their
// own hook events. Native adapters implement the same Decoder interface.
type RecordDecoder struct{}

func (RecordDecoder) Decode(line []byte) (Record, bool, error) {
	if !json.Valid(line) {
		return Record{}, false, errors.New("invalid hook record JSON")
	}
	return DecodeRecord(line)
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$`)

// ExecutionID namespaces a host delivery ID without retaining native handler
// IDs or paths. Hosts reuse deliveryID on retries, and assign it once per run.
func ExecutionID(harness, deliveryID string) (string, error) {
	id := harness + ":" + deliveryID
	if !identifier.MatchString(harness) || !identifier.MatchString(deliveryID) || !identifier.MatchString(id) {
		return "", errors.New("invalid hook execution id")
	}
	return id, nil
}

var label = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var scriptLabel = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// Validate enforces the versioned metadata contract before it crosses the
// collection boundary. Error messages never include rejected input values.
func (r Record) Validate() error {
	if r.Type != "hook_run" {
		return ErrInvalidInput
	}
	if r.Version != 1 && r.Version != 2 {
		return ErrUnsupportedProtocol
	}
	switch r.Harness {
	case "claude", "codex", "openclaw", "hermes", "opencode":
	default:
		return errors.New("unsupported hook harness")
	}
	if !identifier.MatchString(r.ID) || !identifier.MatchString(r.SessionID) {
		return errors.New("invalid hook execution or session id")
	}
	if !label.MatchString(r.Event) || (r.Script != "" && (!scriptLabel.MatchString(r.Script) || r.Script == "." || r.Script == "..")) {
		return errors.New("invalid hook label")
	}
	switch r.Status {
	case "ok", "inject", "deny", "block", "error", "cancelled":
	default:
		return errors.New("invalid hook outcome")
	}
	if r.TS.IsZero() || r.TS.Year() < 1 || r.TS.Year() > 9999 || r.DurationMs < 0 || r.Chars < 0 {
		return errors.New("invalid hook time or count")
	}
	if r.Version == 1 && r.Evidence != nil || r.Version == 2 && r.Evidence == nil {
		return errors.New("hook evidence requires version 2")
	}
	if r.Evidence != nil {
		return r.Evidence.Validate()
	}
	return nil
}

// DecodeRecord reads the common bridge format. Unsupported versions and
// malformed records are recognized but rejected, never treated as tool use.
func DecodeRecord(line []byte) (Record, bool, error) {
	if !bytes.Contains(line, []byte(`"hook_run"`)) {
		return Record{}, false, nil
	}
	var head struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(line, &head) != nil || head.Type != "hook_run" {
		return Record{}, false, nil
	}
	var r Record
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil {
		return Record{}, true, errors.New("invalid hook record")
	}
	if r.Evidence != nil {
		var measured struct {
			DurationMs *int64 `json:"duration_ms"`
			Chars      *int64 `json:"chars"`
		}
		if json.Unmarshal(line, &measured) != nil || (r.Evidence.DurationKnown && measured.DurationMs == nil) || (r.Evidence.CharsKnown && measured.Chars == nil) {
			return Record{}, true, errors.New("known hook measurements require numeric values")
		}
	}
	return r, true, r.Validate()
}
