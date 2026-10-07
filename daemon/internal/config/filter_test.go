package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// The loaded config carries the disabled list it filtered agents by.
func TestLoadKeepsDisabledAgents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("disabled_agents:\n  - claude\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadStrict(path)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.DisabledAgents, []string{"claude"}) {
		t.Fatalf("DisabledAgents = %v, want [claude]", cfg.DisabledAgents)
	}
	for _, d := range cfg.Agents {
		if d.Name == "claude" {
			t.Fatal("claude still defined")
		}
	}
}

func TestFilterDisabledAgents(t *testing.T) {
	all := []AgentDef{
		{Name: "claude"}, {Name: "cursor"}, {Name: "opencode"},
	}
	got := filterDisabledAgents(all, []string{"CURSOR"})
	if len(got) != 2 || got[0].Name != "claude" || got[1].Name != "opencode" {
		t.Fatalf("got %+v", got)
	}
	got2 := filterDisabledAgents(all, []string{"nothere"})
	if len(got2) != 3 {
		t.Fatalf("stale disabled entry must not drop anything: %+v", got2)
	}
	if len(filterDisabledAgents(all, nil)) != 3 {
		t.Fatal("nil disabled must pass through")
	}
}
