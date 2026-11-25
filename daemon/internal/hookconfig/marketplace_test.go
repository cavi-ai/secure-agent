package hookconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestClaudeMarketplaceRegistration(t *testing.T) {
	home := t.TempDir()
	claude := filepath.Join(home, ".claude")
	cache := filepath.Join(claude, "plugins/cache/cavi-ai/secure-agent/1.0")
	write := func(path string, value any) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(value)
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	settings := filepath.Join(claude, "settings.json")
	registry := filepath.Join(claude, "plugins/installed_plugins.json")
	write(settings, map[string]any{"enabledPlugins": map[string]bool{"secure-agent@cavi-ai": true}})
	write(registry, map[string]any{"version": 2, "plugins": map[string]any{"secure-agent@cavi-ai": []any{map[string]any{"scope": "user", "installPath": cache}}}})
	write(filepath.Join(cache, ".claude-plugin/plugin.json"), map[string]any{"name": "secure-agent"})
	hook := map[string]any{"matcher": "*", "hooks": []any{map[string]any{"type": "command", "command": "python3 \"${CLAUDE_PLUGIN_ROOT}/hooks/secret_guard.py\""}}}
	write(filepath.Join(cache, "hooks/hooks.json"), map[string]any{"hooks": map[string]any{"PreToolUse": []any{hook}, "PostToolUse": []any{hook}}})
	for _, name := range []string{"secret_guard.py", "activity_log.py", "injection_scan.py", "guard-rules.json"} {
		write(filepath.Join(cache, "hooks", name), "asset")
	}
	if !ClaudeHookRegistered(settings) {
		t.Fatal("valid user plugin not recognized")
	}
	makeGroup := func(matcher string) map[string]any { return map[string]any{"matcher": matcher, "hooks": hook["hooks"]} }
	write(filepath.Join(cache, "hooks/hooks.json"), map[string]any{"hooks": map[string]any{"PreToolUse": []any{makeGroup("Bash"), makeGroup("Read|Grep|Glob|Write|Edit|MultiEdit|NotebookEdit")}, "PostToolUse": []any{makeGroup(".*")}}})
	if !ClaudeHookRegistered(settings) {
		t.Fatal("previous package shape not recognized")
	}
	write(filepath.Join(cache, "hooks/hooks.json"), map[string]any{"hooks": map[string]any{"PreToolUse": []any{hook}, "PostToolUse": []any{hook}}})
	for _, events := range [][]string{{"PreToolUse"}, {"PostToolUse"}, {"PreToolUse", "PostToolUse"}} {
		hooks := map[string]any{}
		for _, event := range events {
			hooks[event] = []any{map[string]any{"hooks": []any{map[string]any{"command": "python3 " + filepath.Join(home, ".claude/hooks/secret_guard.py")}}}}
		}
		write(settings, map[string]any{"enabledPlugins": map[string]bool{"secure-agent@cavi-ai": true}, "hooks": hooks})
		if !NativeClaudeHookAny(settings) {
			t.Fatalf("missing duplicate detection for %v", events)
		}
	}
	write(settings, map[string]any{"enabledPlugins": map[string]bool{"secure-agent@cavi-ai": true}})
	write(registry, map[string]any{"version": 2, "plugins": map[string]any{"secure-agent@cavi-ai": []any{map[string]any{"scope": "project", "installPath": cache}}}})
	if ClaudeHookRegistered(settings) {
		t.Fatal("project scope accepted")
	}
	write(registry, map[string]any{"version": 2, "plugins": map[string]any{"secure-agent@cavi-ai": []any{map[string]any{"scope": "user", "installPath": home}}}})
	if ClaudeHookRegistered(settings) {
		t.Fatal("outside cache accepted")
	}
	write(registry, map[string]any{"version": 1})
	if ClaudeHookRegistered(settings) {
		t.Fatal("malformed registry accepted")
	}
	write(registry, map[string]any{"version": 2, "plugins": map[string]any{"secure-agent@cavi-ai": []any{map[string]any{"scope": "user", "installPath": cache}}}})
	write(settings, map[string]any{"enabledPlugins": map[string]bool{"secure-agent@cavi-ai": false}})
	if ClaudeHookRegistered(settings) {
		t.Fatal("disabled plugin accepted")
	}
	write(settings, map[string]any{"enabledPlugins": map[string]bool{"secure-agent@cavi-ai": true}})
	os.Remove(filepath.Join(cache, "hooks/secret_guard.py"))
	if ClaudeHookRegistered(settings) {
		t.Fatal("missing asset accepted")
	}
	write(settings, map[string]any{"enabledPlugins": map[string]bool{"secure-agent@cavi-ai": true}, "disableAllHooks": true})
	if ClaudeHookRegistered(settings) {
		t.Fatal("disabled hooks accepted")
	}
}

func TestClaudeHookRegistered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	// Missing file → not registered.
	if ClaudeHookRegistered(path) {
		t.Fatal("missing settings.json must read as unregistered")
	}
	// Only PreToolUse → not fully registered.
	os.WriteFile(path, []byte(`{"hooks":{"PreToolUse":[{"hooks":[{"command":"python3 ~/.claude/hooks/secret_guard.py"}]}]}}`), 0o600)
	if ClaudeHookRegistered(path) {
		t.Fatal("PreToolUse alone must not count as registered")
	}
	// Both events → registered.
	os.WriteFile(path, []byte(`{"hooks":{"PreToolUse":[{"hooks":[{"command":"python3 ~/.claude/hooks/secret_guard.py"}]}],"PostToolUse":[{"hooks":[{"command":"python3 ~/.claude/hooks/secret_guard.py"}]}]}}`), 0o600)
	if !ClaudeHookRegistered(path) {
		t.Fatal("both events registered must read as registered")
	}
}
