package model

import "slices"

// HookHarnesses are the hosts whose hook completions the daemon records, in
// display order. The console's HOOK_HARNESSES mirrors this list; a drift test
// in daemon/internal/wiregen pins it.
var HookHarnesses = []string{"claude", "codex", "openclaw", "hermes", "opencode"}

// IsHookHarness reports whether name is one of HookHarnesses.
func IsHookHarness(name string) bool { return slices.Contains(HookHarnesses, name) }
