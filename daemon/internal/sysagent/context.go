package sysagent

import (
	"encoding/json"
	"fmt"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

const chatContextBytes = 32768

// Reserve transport space for tool schemas, calls and one evidence result.
const initialChatContextBytes = 16384

// Bound the whole serialized context, not just message count. Keep the newest
// user-led suffix; never fabricate a summary of omitted conversation.
func boundedChatContext(system string, history []model.SysAgentMessage) ([]chatMessage, error) {
	var turns []chatMessage
	for _, m := range history {
		if m.Role == "user" || m.Role == "assistant" {
			turns = append(turns, chatMessage{Role: m.Role, Content: m.Content})
		}
	}
	omitted := false
	for {
		for len(turns) > 0 && turns[0].Role != "user" {
			turns = turns[1:]
			omitted = true
		}
		prompt := system
		if omitted {
			prompt += "\nOlder conversation turns were omitted to fit the context budget. Do not assume their contents; ask for missing facts."
		}
		msgs := append([]chatMessage{{Role: "system", Content: prompt}}, turns...)
		body, err := json.Marshal(msgs)
		if err != nil {
			return nil, err
		}
		if len(body) <= initialChatContextBytes && len(turns) > 0 {
			return msgs, nil
		}
		if len(turns) <= 1 {
			return nil, fmt.Errorf("the current message and procedures exceed the chat context budget")
		}
		turns = turns[1:]
		omitted = true
	}
}
