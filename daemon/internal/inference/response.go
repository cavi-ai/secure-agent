package inference

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

const metadataLimit = 64 * 1024

// responseObservation keeps only bounded transient framing and numeric usage.
// Text, tool arguments and response payloads never enter the activity snapshot.
type responseObservation struct {
	input, output         *int64
	model                 string
	done, failed, partial bool
	framed                bool
	line                  []byte
	discarding            bool
}

func count(n *int64) *int64 {
	if n != nil && *n >= 0 {
		return n
	}
	return nil
}
func (o *responseObservation) object(data []byte) {
	var event struct {
		Model  string          `json:"model"`
		Done   bool            `json:"done"`
		Error  json.RawMessage `json:"error"`
		Type   string          `json:"type"`
		Input  *int64          `json:"prompt_eval_count"`
		Output *int64          `json:"eval_count"`
		Usage  struct {
			Prompt     *int64 `json:"prompt_tokens"`
			Completion *int64 `json:"completion_tokens"`
			Input      *int64 `json:"input_tokens"`
			Output     *int64 `json:"output_tokens"`
		} `json:"usage"`
		Message struct {
			Usage struct {
				Input  *int64 `json:"input_tokens"`
				Output *int64 `json:"output_tokens"`
			} `json:"usage"`
		} `json:"message"`
		Response struct {
			Model string `json:"model"`
			Usage struct {
				Input  *int64 `json:"input_tokens"`
				Output *int64 `json:"output_tokens"`
			} `json:"usage"`
		} `json:"response"`
		Choices []struct {
			Finish *string `json:"finish_reason"`
		} `json:"choices"`
	}
	if json.Unmarshal(data, &event) != nil {
		o.partial = true
		return
	}
	if event.Model != "" {
		o.model = bounded(event.Model, 256)
	}
	if event.Response.Model != "" {
		o.model = bounded(event.Response.Model, 256)
	}
	for _, n := range []*int64{event.Input, event.Usage.Prompt, event.Usage.Input, event.Message.Usage.Input, event.Response.Usage.Input} {
		if v := count(n); v != nil {
			o.input = v
		}
	}
	for _, n := range []*int64{event.Output, event.Usage.Completion, event.Usage.Output, event.Message.Usage.Output, event.Response.Usage.Output} {
		if v := count(n); v != nil {
			o.output = v
		}
	}
	o.done = o.done || event.Done || event.Type == "message_stop" || event.Type == "response.completed"
	for _, c := range event.Choices {
		if c.Finish != nil {
			o.done = true
		}
	}
	if len(event.Error) > 0 && string(event.Error) != "null" {
		o.failed = true
	}
	if event.Type == "error" || event.Type == "response.failed" {
		o.failed = true
	}
}
func (o *responseObservation) frame() {
	line := bytes.TrimSpace(o.line)
	o.line = o.line[:0]
	if len(line) == 0 || bytes.HasPrefix(line, []byte(":")) || bytes.HasPrefix(line, []byte("event:")) || bytes.HasPrefix(line, []byte("id:")) || bytes.HasPrefix(line, []byte("retry:")) {
		return
	}
	if bytes.HasPrefix(line, []byte("data:")) {
		line = bytes.TrimSpace(line[5:])
	}
	if bytes.Equal(line, []byte("[DONE]")) {
		o.done = true
		return
	}
	o.object(line)
}
func (o *responseObservation) feed(data []byte) {
	if !o.framed {
		if len(o.line)+len(data) > metadataLimit {
			o.partial = true
			o.discarding = true
			o.line = nil
			return
		}
		if !o.discarding {
			o.line = append(o.line, data...)
		}
		return
	}
	for len(data) > 0 {
		end := bytes.IndexByte(data, '\n')
		part := data
		if end >= 0 {
			part = data[:end]
		}
		if len(o.line)+len(part) > metadataLimit {
			o.partial = true
			o.discarding = true
			o.line = nil
		}
		if !o.discarding {
			o.line = append(o.line, part...)
		}
		if end < 0 {
			break
		}
		if !o.discarding {
			o.frame()
		}
		o.discarding = false
		o.line = o.line[:0]
		data = data[end+1:]
	}
}
func (o *responseObservation) end() {
	if !o.discarding && len(o.line) > 0 {
		if o.framed {
			o.frame()
		} else {
			o.object(o.line)
		}
	}
	o.line = nil
}

func requestModel(data []byte) string {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return ""
	}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return ""
		}
		if key == "model" {
			var model string
			if decoder.Decode(&model) == nil {
				return bounded(model, 256)
			}
			return ""
		}
		var discarded json.RawMessage
		if decoder.Decode(&discarded) != nil {
			return ""
		}
	}
	return ""
}

type prefixBody struct {
	io.Reader
	io.Closer
}

func isFramed(contentType string) bool {
	return strings.Contains(contentType, "event-stream") || strings.Contains(contentType, "ndjson") || strings.Contains(contentType, "jsonl")
}
