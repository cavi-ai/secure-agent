package localmodel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Native Ollama requests carry context and residency controls that its OpenAI
// compatibility route cannot express. Other providers retain their own protocol.
func (t *transport) infer(req *http.Request) (*http.Response, error) {
	if !t.native {
		return t.base.RoundTrip(req)
	}
	defer req.Body.Close()
	data, err := io.ReadAll(io.LimitReader(req.Body, 32769))
	if err != nil || len(data) > 32768 {
		return nil, fmt.Errorf("local model request exceeds byte budget")
	}
	var in map[string]any
	if json.Unmarshal(data, &in) != nil {
		return nil, fmt.Errorf("invalid local model request")
	}
	maxTokens, _ := in["max_tokens"].(float64)
	if maxTokens <= 0 || maxTokens > 4096 {
		maxTokens = 3072
	}
	// A byte is a conservative token upper bound; reserve output explicitly.
	if len(data)+int(maxTokens) > ContextTokens {
		return nil, fmt.Errorf("local model request exceeds context budget")
	}
	messages, ok := in["messages"].([]any)
	if !ok {
		return nil, fmt.Errorf("missing local model messages")
	}
	names := map[string]string{}
	for _, value := range messages {
		m, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid local model message")
		}
		if calls, ok := m["tool_calls"].([]any); ok {
			for _, value := range calls {
				call, ok := value.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("invalid tool call")
				}
				f, ok := call["function"].(map[string]any)
				if !ok {
					return nil, fmt.Errorf("invalid tool function")
				}
				id, _ := call["id"].(string)
				name, _ := f["name"].(string)
				names[id] = name
				if args, ok := f["arguments"].(string); ok {
					var obj map[string]any
					if json.Unmarshal([]byte(args), &obj) != nil {
						return nil, fmt.Errorf("invalid tool arguments")
					}
					f["arguments"] = obj
				}
				delete(call, "id")
				delete(call, "type")
			}
		}
		if id, ok := m["tool_call_id"].(string); ok {
			m["tool_name"] = names[id]
			delete(m, "tool_call_id")
		}
	}
	native := map[string]any{"model": in["model"], "messages": messages, "stream": false, "think": false, "keep_alive": "2m", "options": map[string]any{"num_ctx": ContextTokens, "num_predict": int(maxTokens), "temperature": in["temperature"]}}
	if tools, ok := in["tools"]; ok {
		native["tools"] = tools
	}
	if format, ok := in["response_format"].(map[string]any); ok && format["type"] == "json_object" {
		native["format"] = "json"
	}
	body, err := json.Marshal(native)
	if err != nil {
		return nil, err
	}
	req.URL.Path = "/api/chat"
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.GetBody = nil
	resp, err := t.base.RoundTrip(req)
	if err != nil || resp.StatusCode != 200 {
		return resp, err
	}
	defer resp.Body.Close()
	data, err = io.ReadAll(io.LimitReader(resp.Body, 256*1024+1))
	if err != nil || len(data) > 256*1024 {
		return nil, fmt.Errorf("local model response exceeds byte budget")
	}
	var out struct {
		Message    map[string]any `json:"message"`
		Done       bool           `json:"done"`
		Reason     string         `json:"done_reason"`
		Prompt     int            `json:"prompt_eval_count"`
		Tokens     int            `json:"eval_count"`
		PromptTime int64          `json:"prompt_eval_duration"`
		TokenTime  int64          `json:"eval_duration"`
	}
	if json.Unmarshal(data, &out) != nil || !out.Done || out.Message == nil || out.Reason == "length" {
		return nil, fmt.Errorf("local model returned an incomplete response")
	}
	if calls, ok := out.Message["tool_calls"].([]any); ok {
		serial := t.pool.nextCall.Add(1)
		for i, value := range calls {
			call, ok := value.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("invalid model tool call")
			}
			f, ok := call["function"].(map[string]any)
			if !ok {
				return nil, fmt.Errorf("invalid model tool function")
			}
			args, err := json.Marshal(f["arguments"])
			if err != nil {
				return nil, err
			}
			f["arguments"] = string(args)
			call["id"] = fmt.Sprintf("local_%d_%d", serial, i)
			call["type"] = "function"
		}
	}
	adapted := map[string]any{"choices": []any{map[string]any{"message": out.Message, "finish_reason": out.Reason}}, "usage": map[string]int{"prompt_tokens": out.Prompt, "completion_tokens": out.Tokens}, "prompt_eval_duration": out.PromptTime, "eval_duration": out.TokenTime}
	data, err = json.Marshal(adapted)
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(data))
	resp.ContentLength = int64(len(data))
	resp.Header.Del("Content-Length")
	resp.Header.Set("Content-Type", "application/json")
	return resp, nil
}

// Residency is provider-reported state, never an inference or unload request.
type Residency struct {
	Format    string `json:"format,omitempty"`
	Available bool   `json:"available"`
	Loaded    bool   `json:"loaded"`
	Bytes     int64  `json:"bytes"`
	Context   int    `json:"context"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

func ResidencyAt(ctx context.Context, client *http.Client, endpoint, model string) Residency {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(endpoint, "/")+"/api/ps", nil)
	if err != nil {
		return Residency{}
	}
	resp, err := client.Do(req)
	if err != nil {
		return Residency{}
	}
	defer resp.Body.Close()
	var out struct {
		Models []struct {
			Details struct {
				Format string `json:"format"`
			} `json:"details"`
			Name    string
			Model   string
			Size    int64
			Context int    `json:"context_length"`
			Expires string `json:"expires_at"`
		}
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 32768)).Decode(&out) != nil {
		return Residency{}
	}
	r := Residency{Available: true}
	for _, m := range out.Models {
		if m.Name == model || m.Model == model || m.Name == model+":latest" {
			r.Loaded = true
			r.Bytes = m.Size
			r.Context = m.Context
			r.ExpiresAt = m.Expires
			r.Format = m.Details.Format
		}
	}
	return r
}
