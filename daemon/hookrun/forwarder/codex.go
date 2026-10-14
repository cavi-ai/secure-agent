package forwarder

import (
	"encoding/json"
	"errors"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
	"github.com/cavi-ai/secure-agent/daemon/hookrun/codex"
)

// Codex adapts a host's native app-server notification callback. It does not
// launch Codex or take ownership of the host's subscription or hook execution.
type Codex struct{ *Client }

func NewCodex(config Config) (*Codex, error) {
	if config.Harness != "" && config.Harness != "codex" {
		return nil, errors.New("Codex forwarder requires codex harness")
	}
	config.Harness = "codex"
	c, err := New(config)
	if err != nil {
		return nil, err
	}
	return &Codex{Client: c}, nil
}

// Submit assigns one opaque delivery ID per native completion and normalizes
// it before queuing. An empty ID with no error means an unrelated notification.
// Call once per completion; the client owns retries thereafter. The returned
// ID is the normalized execution ID, including its codex namespace.
func (c *Codex) Submit(notification []byte) (string, error) {
	if len(notification) > 1024*1024 {
		return "", c.captureResult(hookrun.ErrInvalidInput)
	}
	var head struct {
		Method string `json:"method"`
	}
	if json.Unmarshal(notification, &head) != nil {
		return "", c.captureResult(hookrun.ErrInvalidInput)
	}
	if head.Method != "hook/completed" {
		return "", nil
	}
	id, err := newID()
	if err != nil {
		return "", c.captureResult(err)
	}
	envelope, err := json.Marshal(struct {
		ID           string          `json:"id"`
		Notification json.RawMessage `json:"notification"`
	}{id, notification})
	if err != nil {
		return "", c.captureResult(hookrun.ErrInvalidInput)
	}
	return c.submit(envelope, codex.Decoder{})
}
