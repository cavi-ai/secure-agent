// Package hermes adapts observed Hermes plugin callback results.
package hermes

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
)

type Decoder struct{}

var _ hookrun.Decoder = Decoder{}

func (Decoder) Decode(line []byte) (hookrun.Record, bool, error) {
	c, r, ok, err := hookrun.DecodeCompletion(line, "hermes")
	if err != nil || !ok || c.State != "completed" || len(c.Result) == 0 {
		return r, ok, err
	}
	if c.Event != "pre_tool_call" && c.Event != "pre_llm_call" && c.Event != "pre_verify" {
		return r, true, nil
	}
	raw := bytes.TrimSpace(c.Result)
	plainContext := len(raw) > 0 && raw[0] == '"'
	var result struct {
		Action   string `json:"action"`
		Decision string `json:"decision"`
		Message  string `json:"message"`
		Reason   string `json:"reason"`
		Context  string `json:"context"`
	}
	if len(raw) > 0 && raw[0] == '"' && c.Event == "pre_llm_call" {
		if json.Unmarshal(raw, &result.Context) != nil {
			return hookrun.Record{}, true, errors.New("invalid Hermes context result")
		}
	} else if len(raw) > 0 && raw[0] == '{' {
		if json.Unmarshal(raw, &result) != nil {
			return hookrun.Record{}, true, errors.New("invalid Hermes hook result")
		}
	} else {
		return r, true, nil
	}
	r.Evidence.CharsKnown = true
	switch c.Event {
	case "pre_tool_call":
		if result.Action == "block" && result.Message != "" {
			r.Status = "block"
			r.Chars = int64(utf8.RuneCountInString(result.Message))
		}
	case "pre_llm_call":
		if result.Context != "" && (!plainContext || strings.TrimSpace(result.Context) != "") {
			r.Status = "inject"
			r.Chars = int64(utf8.RuneCountInString(result.Context))
		}
		n := r.Chars
		r.Evidence.ContextChars = &n
	case "pre_verify":
		action := result.Action
		if action == "" {
			action = result.Decision
		}
		action = strings.ToLower(strings.TrimSpace(action))
		message := result.Message
		if message == "" {
			message = result.Reason
		}
		message = strings.TrimSpace(message)
		if (action == "continue" || action == "block") && message != "" {
			r.Status = "block"
			r.Chars = int64(utf8.RuneCountInString(message))
		}
	}
	return r, true, nil
}
