package api

import "github.com/cavi-ai/secure-agent/daemon/internal/hookconfig"

// Filesystem probes are gathered at the boundary, never during ranking.
func guardHookUnregisteredItem(status Status) *PostureItem {
	if !activeHarness(status, "claude") {
		return nil
	}
	settings, err := hookconfig.ClaudeSettingsPath()
	if err != nil {
		return nil
	}
	if hookconfig.ClaudeMarketplacePath(settings) != "" && hookconfig.NativeClaudeHookAny(settings) {
		return &PostureItem{Kind: "guard_hook_duplicate", ID: "claude-hook-duplicate", Title: "Claude Code has duplicate guard routes", Severity: 2, Detail: "Both marketplace and manual hooks are configured. Remove one route to avoid duplicate hooks."}
	}
	if !hookconfig.ClaudeHookRegistered(settings) {
		return &PostureItem{
			Kind: "guard_hook_unregistered", ID: "claude-hook",
			Title:    "Claude Code guard hook is not registered",
			Severity: 2,
			Detail:   "~/.claude/settings.json has no guard hook, so the PreToolUse guard never runs — install it from Setup & Permissions",
		}
	}
	return nil
}
