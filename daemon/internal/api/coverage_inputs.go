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
	if claudeMarketplacePath(settings) != "" && nativeClaudeHookAny(settings) {
		return &PostureItem{Kind: "guard_hook_duplicate", ID: "claude-hook-duplicate", Title: "Claude Code has duplicate guard routes", Severity: 2, Detail: "Both marketplace and manual hooks are configured. Remove one route to avoid duplicate hooks."}
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
		DisableAllHooks bool            `json:"disableAllHooks"`
		EnabledPlugins  map[string]bool `json:"enabledPlugins"`
		Hooks           map[string][]struct {
			Hooks []struct {
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if json.Unmarshal(data, &root) != nil {
		return false
	}
	if root.DisableAllHooks {
		return false
	}
	if root.EnabledPlugins["secure-agent@cavi-ai"] {
		return claudeMarketplacePath(path) != ""
	}
	return nativeClaudeHookRegistered(path)
}

func nativeClaudeHookRegistered(path string) bool {
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

func nativeClaudeHookAny(path string) bool {
	b, err := os.ReadFile(path)
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
	if json.Unmarshal(b, &root) != nil {
		return false
	}
	home := filepath.Dir(filepath.Dir(path))
	script := filepath.Join(home, ".claude/hooks/secret_guard.py")
	quoted := "python3 '" + strings.ReplaceAll(script, "'", "'\"'\"'") + "'"
	plain := "python3 " + script
	for _, event := range []string{"PreToolUse", "PostToolUse"} {
		for _, group := range root.Hooks[event] {
			for _, hook := range group.Hooks {
				if hook.Command == quoted || hook.Command == plain {
					return true
				}
			}
		}
	}
	return false
}

// claudeMarketplacePath accepts only a user installation rooted in Claude's cache.
func claudeMarketplacePath(settings string) string {
	readJSON := func(path string, v any) bool {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
			return false
		}
		b, err := os.ReadFile(path)
		return err == nil && json.Unmarshal(b, v) == nil
	}
	var settingsRoot struct {
		DisableAllHooks bool            `json:"disableAllHooks"`
		EnabledPlugins  map[string]bool `json:"enabledPlugins"`
	}
	if !readJSON(settings, &settingsRoot) || settingsRoot.DisableAllHooks || !settingsRoot.EnabledPlugins["secure-agent@cavi-ai"] {
		return ""
	}
	claude := filepath.Dir(settings)
	var data struct {
		Version int `json:"version"`
		Plugins map[string][]struct {
			Scope       string `json:"scope"`
			InstallPath string `json:"installPath"`
		} `json:"plugins"`
	}
	if !readJSON(filepath.Join(claude, "plugins", "installed_plugins.json"), &data) || data.Version != 2 {
		return ""
	}
	home, err := filepath.EvalSymlinks(filepath.Dir(claude))
	if err != nil {
		return ""
	}
	base := filepath.Join(home, ".claude/plugins/cache/cavi-ai/secure-agent")
	realBase, err := filepath.EvalSymlinks(base)
	if err != nil || realBase != base {
		return ""
	}
	for _, entry := range data.Plugins["secure-agent@cavi-ai"] {
		if entry.Scope != "user" || !filepath.IsAbs(entry.InstallPath) || filepath.Clean(entry.InstallPath) != entry.InstallPath {
			continue
		}
		resolved, err := filepath.EvalSymlinks(entry.InstallPath)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(base, resolved)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
			continue
		}
		read := func(name string, v any) bool {
			path := filepath.Join(resolved, name)
			real, err := filepath.EvalSymlinks(path)
			return err == nil && real == path && readJSON(path, v)
		}
		var manifest struct {
			Name string `json:"name"`
		}
		if !read(".claude-plugin/plugin.json", &manifest) || manifest.Name != "secure-agent" {
			continue
		}
		var cfg struct {
			Hooks map[string][]struct {
				Matcher string `json:"matcher"`
				Hooks   []struct {
					Type    string `json:"type"`
					Command string `json:"command"`
				} `json:"hooks"`
			} `json:"hooks"`
		}
		if !read("hooks/hooks.json", &cfg) {
			continue
		}
		valid := true
		matches := func(event string, expected []string) bool {
			groups := cfg.Hooks[event]
			if len(groups) != len(expected) {
				return false
			}
			for i, group := range groups {
				if group.Matcher != expected[i] || len(group.Hooks) != 1 || group.Hooks[0].Type != "command" || group.Hooks[0].Command != `python3 "${CLAUDE_PLUGIN_ROOT}/hooks/secret_guard.py"` {
					return false
				}
			}
			return true
		}
		valid = (matches("PreToolUse", []string{"*"}) && matches("PostToolUse", []string{"*"})) || (matches("PreToolUse", []string{"Bash", "Read|Grep|Glob|Write|Edit|MultiEdit|NotebookEdit"}) && matches("PostToolUse", []string{".*"}))
		for _, name := range []string{"secret_guard.py", "activity_log.py", "injection_scan.py", "guard-rules.json"} {
			path := filepath.Join(resolved, "hooks", name)
			real, err := filepath.EvalSymlinks(path)
			if err != nil || real != path {
				valid = false
				continue
			}
			info, err := os.Stat(path)
			if err != nil || !info.Mode().IsRegular() {
				valid = false
			}
		}
		if valid {
			return resolved
		}
	}
	return ""
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
	case "launch-item-change":
		return "Agent changed a background item"
	case "trust-change":
		return "Agent changed what macOS trusts"
	case "xprotect-detection":
		return "XProtect detected malware"
	case "proxy-prompt-injection":
		return "Prompt injection in a response"
	case "proxy-inspection-incomplete":
		return "Proxy request inspection was incomplete"
	case "secret-in-transcript":
		return "Secret appeared in an agent transcript"
	case "untrusted-egress":
		return "Data sent after reading untrusted content"
	case "proxy-untrusted-egress":
		return "Connection refused after reading untrusted content"
	case "proxy-untrusted-egress-monitored":
		return "Connection after reading untrusted content"
	default:
		return rule
	}
}

func uninspectedTitle(n int) string {
	if n == 1 {
		return "1 endpoint reached outside the inspection proxy"
	}
	return fmt.Sprintf("%d endpoints reached outside the inspection proxy", n)
}
