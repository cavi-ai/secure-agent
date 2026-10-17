// A tracked tool caller for the live guard workflow check. It invokes the
// production Claude hook protocol and reads the fixture only after approval.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	if len(os.Args) != 5 {
		panic("expected python, hook and two resource paths")
	}
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		path := os.Args[3]
		if scanner.Text() == "observe" {
			path = "README.md"
		} else if scanner.Text() == "other" {
			path = os.Args[4]
		} else if scanner.Text() != "read" {
			panic("unknown fixture operation")
		}
		payload := map[string]any{
			"hook_event_name": "PreToolUse", "tool_name": "Read",
			"session_id": os.Getenv("SECURE_AGENT_SESSION_ID"),
			"tool_input": map[string]string{"file_path": path},
		}
		input, err := json.Marshal(payload)
		if err != nil {
			panic(err)
		}
		command := exec.Command(os.Args[1], os.Args[2])
		command.Stdin = bytes.NewReader(input)
		command.Stderr = os.Stderr
		output, err := command.Output()
		if err != nil {
			panic(err)
		}
		var verdict struct {
			Permission         string `json:"permission"`
			HookSpecificOutput struct {
				PermissionDecision string `json:"permissionDecision"`
			} `json:"hookSpecificOutput"`
		}
		if err := json.Unmarshal(output, &verdict); err != nil {
			panic(err)
		}
		if verdict.Permission == "" {
			verdict.Permission = verdict.HookSpecificOutput.PermissionDecision
		}
		read := 0
		if verdict.Permission == "allow" {
			content, err := os.ReadFile(path)
			if err != nil {
				panic(err)
			}
			read = len(content)
			payload["hook_event_name"] = "PostToolUse"
			postInput, err := json.Marshal(payload)
			if err != nil {
				panic(err)
			}
			post := exec.Command(os.Args[1], filepath.Join(filepath.Dir(os.Args[2]), "activity_log.py"))
			post.Stdin = bytes.NewReader(postInput)
			post.Stderr = os.Stderr
			if err := post.Run(); err != nil {
				panic(err)
			}
		}
		result, err := json.Marshal(map[string]any{"permission": verdict.Permission, "bytes_read": read})
		if err != nil {
			panic(err)
		}
		fmt.Println(string(result))
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}
}
