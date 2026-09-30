package sysagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// ollamaInfo is what one probe of the endpoint found.
type ollamaInfo struct {
	Reachable    bool
	Version      string
	Models       []string
	Capabilities map[string][]string
	Err          string
}

// probeTimeout bounds one probe: the console waits on it.
const probeTimeout = 1500 * time.Millisecond

// probe asks Ollama for its version and the models it has pulled.
func probe(ctx context.Context, client *http.Client, endpoint string) ollamaInfo {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	var tags struct {
		Models []struct {
			Name         string   `json:"name"`
			Capabilities []string `json:"capabilities"`
		} `json:"models"`
	}
	if err := getJSON(ctx, client, endpoint+"/api/tags", &tags); err != nil {
		return ollamaInfo{Err: err.Error()}
	}
	info := ollamaInfo{Reachable: true, Models: []string{}, Capabilities: map[string][]string{}}
	for _, m := range tags.Models {
		if m.Name != "" {
			info.Models = append(info.Models, m.Name)
			info.Capabilities[m.Name] = m.Capabilities
		}
	}
	sort.Strings(info.Models)
	var v struct {
		Version string `json:"version"`
	}
	if getJSON(ctx, client, endpoint+"/api/version", &v) == nil {
		info.Version = v.Version
	}
	return info
}

func getJSON(ctx context.Context, client *http.Client, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s", url, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// hasModel reports whether name is pulled; "qwen3" matches "qwen3:latest".
func (o ollamaInfo) hasModel(name string) bool {
	for _, m := range o.Models {
		if m == name || m == name+":latest" {
			return true
		}
	}
	return false
}

// Older Ollama versions omit capabilities. Preserve compatibility there,
// but never auto-select (or dispatch) a model explicitly marked embedding-only.
func (o ollamaInfo) supportsChat(name string) bool {
	capabilities, ok := o.Capabilities[name]
	if !ok {
		capabilities, ok = o.Capabilities[name+":latest"]
	}
	if !ok || len(capabilities) == 0 {
		return true
	}
	for _, capability := range capabilities {
		if capability == "completion" {
			return true
		}
	}
	return false
}

// versionAtLeast compares dotted release numbers; an unknown version
// passes (the harness reports its own error).
func versionAtLeast(have, want string) bool {
	if have == "" || want == "" {
		return true
	}
	h, w := versionParts(have), versionParts(want)
	for i := 0; i < 3; i++ {
		if h[i] != w[i] {
			return h[i] > w[i]
		}
	}
	return true
}

var versionRE = regexp.MustCompile(`^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?`)

func versionParts(v string) [3]int {
	var out [3]int
	m := versionRE.FindStringSubmatch(strings.TrimSpace(v))
	for i := 1; m != nil && i < len(m); i++ {
		out[i-1], _ = strconv.Atoi(m[i])
	}
	return out
}

// chatMessage is one OpenAI-compatible chat message.
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatTimeout bounds one reply: a local model may load cold and think.
const chatTimeout = 5 * time.Minute

// chatMaxTokens bounds one reply.
const chatMaxTokens = 3072

var thinkRE = regexp.MustCompile(`(?s)<think>.*?</think>`)

// chat sends msgs to Ollama's OpenAI-compatible endpoint and returns the
// answer with any reasoning trace removed.
func chat(ctx context.Context, client *http.Client, endpoint, modelName string, msgs []chatMessage) (string, *model.SysAgentUsage, error) {
	body, _ := json.Marshal(map[string]any{
		"model":       modelName,
		"messages":    msgs,
		"temperature": 0.2,
		"max_tokens":  chatMaxTokens,
		"stream":      false,
		// Ollama's switch for reasoning models (qwen3 et al): answer, do
		// not spend the budget on a trace.
		"think": false,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("the model server answered %s", resp.Status)
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content   string            `json:"content"`
				ToolCalls []json.RawMessage `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
		PromptEvalCount    int   `json:"prompt_eval_count"`
		EvalCount          int   `json:"eval_count"`
		PromptEvalDuration int64 `json:"prompt_eval_duration"`
		EvalDuration       int64 `json:"eval_duration"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", nil, fmt.Errorf("the model server's answer is not JSON: %w", err)
	}
	if len(out.Choices) == 0 {
		return "", nil, fmt.Errorf("the model returned no answer")
	}
	text := strings.TrimSpace(thinkRE.ReplaceAllString(out.Choices[0].Message.Content, ""))
	if text == "" {
		return "", nil, fmt.Errorf("the model returned an empty answer")
	}
	usage := &model.SysAgentUsage{Model: modelName, PromptTokens: out.Usage.PromptTokens,
		CompletionTokens: out.Usage.CompletionTokens, ElapsedMS: time.Since(started).Milliseconds(),
		ToolCalls: len(out.Choices[0].Message.ToolCalls)}
	if usage.PromptTokens == 0 {
		usage.PromptTokens = out.PromptEvalCount
	}
	if usage.CompletionTokens == 0 {
		usage.CompletionTokens = out.EvalCount
	}
	if out.PromptEvalDuration > 0 {
		usage.PromptTokensPerSecond = float64(usage.PromptTokens) * 1e9 / float64(out.PromptEvalDuration)
	}
	if out.EvalDuration > 0 {
		usage.OutputTokensPerSecond = float64(usage.CompletionTokens) * 1e9 / float64(out.EvalDuration)
	}
	return text, usage, nil
}
