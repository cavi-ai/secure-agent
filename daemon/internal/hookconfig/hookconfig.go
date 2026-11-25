// Package hookconfig reads an agent's settings file and reports whether the
// guard hook is registered.
package hookconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// ClaudeSettingsPath is the user-level Claude Code settings file the guard
// hook registers in.
func ClaudeSettingsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude", "settings.json"), nil
}

// ClaudeHookRegistered reports whether settings.json registers the guard hook
// for both PreToolUse and PostToolUse. A missing/unreadable file is not
// registered.
func ClaudeHookRegistered(path string) bool {
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
		return ClaudeMarketplacePath(path) != ""
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

// NativeClaudeHookAny reports whether settings.json runs the manually
// installed guard script for PreToolUse or PostToolUse.
func NativeClaudeHookAny(path string) bool {
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

// ClaudeMarketplacePath accepts only a user installation rooted in Claude's cache.
func ClaudeMarketplacePath(settings string) string {
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
