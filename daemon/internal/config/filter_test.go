package config

import "testing"

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
