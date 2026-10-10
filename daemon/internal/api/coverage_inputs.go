package api

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Filesystem probes are gathered at the boundary, never during ranking.
func guardHookUnregisteredItem(status Status) *PostureItem {
	if !activeHarness(status, "claude") {
		return nil
	}
	settings, err := claudeSettingsPath()
	if err != nil {
		return nil
	}
	if !claudeHookRegistered(settings) {
		return &PostureItem{
			Kind: "guard_hook_unregistered", ID: "claude-hook",
			Title:    "Claude Code guard hook is not registered",
			Severity: 2,
			Detail:   "~/.claude/settings.json has no guard hook, so the PreToolUse guard never runs — install it from Setup & Permissions",
		}
	}
	return nil
}

// claudeSettingsPath is the user-level Claude Code settings file the guard
// hook registers in.
func claudeSettingsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude", "settings.json"), nil
}

// claudeHookRegistered reports whether settings.json registers the guard hook
// for both PreToolUse and PostToolUse. A missing/unreadable file is not
// registered.
func claudeHookRegistered(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var root struct {
		Hooks map[string][]struct {
			Hooks []struct {
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if json.Unmarshal(data, &root) != nil {
		return false
	}
	guard := func(eventName string) bool {
		for _, group := range root.Hooks[eventName] {
			for _, h := range group.Hooks {
				if strings.Contains(h.Command, ".claude/hooks/secret_guard.py") {
					return true
				}
			}
		}
		return false
	}
	return guard("PreToolUse") && guard("PostToolUse")
}

// humanCollectorTitle maps collector process names to operator language —
// "Monitor eslogger is abandoned" is jargon; "File monitoring is off" is not.
func humanCollectorTitle(name string, abandoned bool) string {
	what := map[string]string{
		"eslogger":    "File monitoring",
		"netsampler":  "Network sampling",
		"transcript":  "Transcript scanning",
		"proxyserver": "Egress inspection",
		"advisor":     "Local advisor",
	}[name]
	if what == "" {
		what = "Monitor " + name
	}
	if abandoned {
		return what + " keeps stopping"
	}
	return what + " is off"
}

// humanCollectorDetail pairs the raw error with the likely fix.
func humanCollectorDetail(name, lastErr string) string {
	var hint string
	switch name {
	case "eslogger":
		// eslogger crash-loops almost always mean Full Disk Access is missing.
		hint = "usually missing Full Disk Access — open Setup & Permissions in the menu bar"
	case "netsampler":
		hint = "restart Secure Agent from the menu bar"
	case "proxyserver":
		hint = "check whether another process holds the proxy port"
	case "transcript":
		hint = "restart Secure Agent from the menu bar"
	case "advisor":
		hint = "check the local model server (default 127.0.0.1:8080)"
	}
	if lastErr == "" {
		return hint
	}
	if hint == "" {
		return lastErr
	}
	return hint + " · " + lastErr
}

// humanFlagTitle maps rule ids to operator language (mirrors the menubar's
// NotificationManager titles; kept in sync manually until a shared table).
func humanFlagTitle(rule string) string {
	switch rule {
	case "proxy-secret-leak":
		return "Secret leaving in agent traffic"
	case "sensitive-read-then-connect":
		return "Sensitive file read near an outside connection"
	case "keychain-access":
		return "Agent touched the keychain"
	case "keychain-security-cli":
		return "Agent ran the macOS keychain tool"
	case "tcc-tamper":
		return "Agent modified macOS privacy permissions (TCC)"
	case "proxy-prompt-injection":
		return "Prompt injection in a response"
	case "proxy-inspection-incomplete":
		return "Proxy request inspection was incomplete"
	case "secret-in-transcript":
		return "Secret appeared in an agent transcript"
	default:
		return rule
	}
}

func uninspectedTitle(n int) string {
	if n == 1 {
		return "1 connection bypassed the egress firewall"
	}
	return fmt.Sprintf("%d connections bypassed the egress firewall", n)
}
