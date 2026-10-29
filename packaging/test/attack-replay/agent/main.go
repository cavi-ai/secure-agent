// A tool-calling agent for the attack replay. Each stdin line is one step: a
// tool call runs the production hook before and after the tool, as Claude Code
// does, and the tool runs only when the hook allows it; an autoload step
// fetches a URL the way a client renders a markdown image, with no hook.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"time"
)

type step struct {
	Tool     string         `json:"tool"`
	Input    map[string]any `json:"input"`
	Autoload string         `json:"autoload"`
}

type result struct {
	Permission string `json:"permission,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Output     string `json:"output"`
	Status     int    `json:"status,omitempty"`
}

func main() {
	if len(os.Args) != 3 {
		panic("expected python and hook paths")
	}
	python, hook := os.Args[1], os.Args[2]
	proxy, err := url.Parse(os.Getenv("SA_REPLAY_PROXY"))
	if err != nil {
		panic(err)
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		var s step
		if err := json.Unmarshal(scanner.Bytes(), &s); err != nil {
			panic(err)
		}
		var r result
		if s.Autoload != "" {
			r.Status, r.Output = fetch(client, s.Autoload)
		} else {
			r = call(python, hook, client, s)
		}
		line, err := json.Marshal(r)
		if err != nil {
			panic(err)
		}
		fmt.Println(string(line))
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}
}

func call(python, hook string, client *http.Client, s step) result {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	payload := map[string]any{
		"hook_event_name": "PreToolUse", "tool_name": s.Tool, "tool_input": s.Input,
		"session_id": os.Getenv("SECURE_AGENT_SESSION_ID"), "cwd": cwd,
	}
	var verdict struct {
		Permission         string `json:"permission"`
		AgentMessage       string `json:"agent_message"`
		HookSpecificOutput struct {
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(runHook(python, hook, payload), &verdict); err != nil {
		panic(err)
	}
	r := result{Permission: verdict.Permission, Reason: verdict.AgentMessage}
	if r.Permission == "" {
		r.Permission = verdict.HookSpecificOutput.PermissionDecision
		r.Reason = verdict.HookSpecificOutput.PermissionDecisionReason
	}
	if r.Permission == "" {
		r.Permission = "allow"
	}
	if r.Permission != "allow" {
		return r
	}
	switch s.Tool {
	case "Read":
		content, err := os.ReadFile(s.Input["file_path"].(string))
		if err != nil {
			panic(err)
		}
		r.Output = string(content)
	case "Bash":
		out, _ := exec.Command("/bin/sh", "-c", s.Input["command"].(string)).CombinedOutput()
		r.Output = string(out)
	case "WebFetch":
		r.Status, r.Output = fetch(client, s.Input["url"].(string))
	default:
		panic("unknown tool " + s.Tool)
	}
	payload["hook_event_name"] = "PostToolUse"
	payload["tool_response"] = map[string]any{"content": r.Output}
	runHook(python, hook, payload)
	return r
}

func runHook(python, hook string, payload map[string]any) []byte {
	input, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	command := exec.Command(python, hook)
	command.Stdin = bytes.NewReader(input)
	command.Stderr = os.Stderr
	out, err := command.Output()
	if err != nil {
		panic(err)
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return []byte("{}")
	}
	return out
}

func fetch(client *http.Client, target string) (int, string) {
	resp, err := client.Get(target)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var head bytes.Buffer
	for k, v := range resp.Header {
		fmt.Fprintf(&head, "%s: %s\n", k, v[0])
	}
	return resp.StatusCode, head.String() + "\n" + string(body)
}
