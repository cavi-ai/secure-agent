// Package openclaw adapts observed OpenClaw plugin-handler results.
package openclaw

import (
	"encoding/json"
	"errors"
	"unicode/utf8"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
)

type Decoder struct{}

var _ hookrun.Decoder = Decoder{}

func (Decoder) Decode(line []byte) (hookrun.Record, bool, error) {
	c, r, ok, err := hookrun.DecodeCompletion(line, "openclaw")
	if err != nil || !ok || c.State != "completed" || len(c.Result) == 0 {
		return r, ok, err
	}
	var result struct {
		Block                bool   `json:"block"`
		BlockReason          string `json:"blockReason"`
		Cancel               bool   `json:"cancel"`
		SystemPrompt         string `json:"systemPrompt"`
		PrependContext       string `json:"prependContext"`
		AppendContext        string `json:"appendContext"`
		PrependSystemContext string `json:"prependSystemContext"`
		AppendSystemContext  string `json:"appendSystemContext"`
		Action               string `json:"action"`
		Retry                struct {
			Instruction string `json:"instruction"`
		} `json:"retry"`
	}
	switch c.Event {
	case "before_tool_call", "before_message_write", "before_prompt_build", "before_agent_start", "before_agent_finalize", "message_sending", "reply_payload_sending":
		if json.Unmarshal(c.Result, &result) != nil {
			return hookrun.Record{}, true, errors.New("invalid OpenClaw hook result")
		}
	default:
		return r, true, nil
	}
	switch c.Event {
	case "before_tool_call", "before_message_write":
		if result.Block {
			r.Status = "block"
			r.Chars = int64(utf8.RuneCountInString(result.BlockReason))
		}
	case "before_prompt_build", "before_agent_start":
		for _, text := range []string{result.SystemPrompt, result.PrependContext, result.AppendContext, result.PrependSystemContext, result.AppendSystemContext} {
			r.Chars += int64(utf8.RuneCountInString(text))
		}
		if r.Chars > 0 {
			r.Status = "inject"
		}
	case "message_sending", "reply_payload_sending":
		if result.Cancel {
			r.Status = "block"
		}
	case "before_agent_finalize":
		if result.Action == "revise" {
			r.Status = "block"
			r.Chars = int64(utf8.RuneCountInString(result.Retry.Instruction))
		}
	}
	return r, true, nil
}
