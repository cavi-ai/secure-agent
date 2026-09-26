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
)

// ollamaInfo is what one probe of the endpoint found.
type ollamaInfo struct {
	Reachable bool
	Version   string
	Models    []string
	Err       string
}

// probeTimeout bounds one probe: the console waits on it.
const probeTimeout = 1500 * time.Millisecond

// probe asks Ollama for its version and the models it has pulled.
func probe(ctx context.Context, client *http.Client, endpoint string) ollamaInfo {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	var tags struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := getJSON(ctx, client, endpoint+"/api/tags", &tags); err != nil {
		return ollamaInfo{Err: err.Error()}
	}
	info := ollamaInfo{Reachable: true, Models: []string{}}
	for _, m := range tags.Models {
		if m.Name != "" {
			info.Models = append(info.Models, m.Name)
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
func chat(ctx context.Context, client *http.Client, endpoint, modelName string, msgs []chatMessage) (string, error) {
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
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the model server answered %s", resp.Status)
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("the model server's answer is not JSON: %w", err)
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("the model returned no answer")
	}
	text := strings.TrimSpace(thinkRE.ReplaceAllString(out.Choices[0].Message.Content, ""))
	if text == "" {
		return "", fmt.Errorf("the model returned an empty answer")
	}
	return text, nil
}
