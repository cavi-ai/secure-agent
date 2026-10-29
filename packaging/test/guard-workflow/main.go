// A tracked tool caller for the live guard workflow check. It invokes the
// production Claude hook protocol and reads the fixture only after approval.
// Shell commands are only asked about, never run.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) != 5 {
		panic("expected python, hook and two resource paths")
	}
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		// "taint" fetches a web page; "bash <command>" asks the hook about a
		// shell command and never runs it.
		if scanner.Text() == "taint" {
			hook(map[string]any{
				"hook_event_name": "PostToolUse", "tool_name": "WebFetch",
				"session_id":    os.Getenv("SECURE_AGENT_SESSION_ID"),
				"tool_input":    map[string]string{"url": "https://example.com/page"},
				"tool_response": map[string]string{"content": "page text"},
			})
			report("allow", 0)
			continue
		}
		if command, ok := strings.CutPrefix(scanner.Text(), "bash "); ok {
			report(hook(map[string]any{
				"hook_event_name": "PreToolUse", "tool_name": "Bash",
				"session_id": os.Getenv("SECURE_AGENT_SESSION_ID"),
				"tool_input": map[string]string{"command": command},
			}), 0)
			continue
		}
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
		permission := hook(payload)
		read := 0
		if permission == "allow" {
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
		report(permission, read)
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}
}

// hook runs the guard hook on one payload and returns its permission, "" when
// it printed nothing (PostToolUse).
func hook(payload map[string]any) string {
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
	if len(bytes.TrimSpace(output)) == 0 {
		return ""
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
	return verdict.Permission
}

func report(permission string, read int) {
	result, err := json.Marshal(map[string]any{"permission": permission, "bytes_read": read})
	if err != nil {
		panic(err)
	}
	fmt.Println(string(result))
}
