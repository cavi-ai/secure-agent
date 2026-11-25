package sysagent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

type toolScenario struct {
	Name      string          `json:"name"`
	Arguments []string        `json:"arguments"`
	Valid     json.RawMessage `json:"valid"`
	Invalid   json.RawMessage `json:"invalid"`
}

type toolScore struct {
	Name   string   `json:"name"`
	Points int      `json:"points"`
	Max    int      `json:"max"`
	Lost   []string `json:"lost"`
}

// Scores every tool replyScope.tools exposes: declared properties match the
// documented arguments, Agent.readTool accepts them and rejects an invalid
// identifying argument. A tool without a scenario, or a scenario without a
// tool, fails the test. SECURE_AGENT_TOOL_SCORES receives the scores as JSON.
func TestAgentToolScenarios(t *testing.T) {
	path := os.Getenv("SECURE_AGENT_TOOL_SCENARIOS")
	if path == "" {
		path = filepath.Join("..", "..", "..", "packaging", "test", "agent-scenarios", "tools.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Finding struct {
			ID        string `json:"id"`
			SessionID string `json:"session_id"`
		} `json:"finding"`
		Tools []toolScenario `json:"tools"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	a, st := testAgent(t, "http://localhost", nil)
	workdir := filepath.Join(a.home, "project")
	if _, err := st.PutFlag(model.Flag{ID: doc.Finding.ID, Rule: "scenario", Severity: 1, TS: time.Now(), SessionID: doc.Finding.SessionID, Workspace: workdir}); err != nil {
		t.Fatal(err)
	}
	msg := model.SysAgentMessage{FlagIDs: []string{doc.Finding.ID}, Workdir: workdir}
	// The first reply records the finding's workspace fact; the next reply
	// exposes search_memory over it.
	a.captureScope(msg)
	scope := a.captureScope(msg)

	scenarios := map[string]toolScenario{}
	for _, s := range doc.Tools {
		scenarios[s.Name] = s
	}
	var scores []toolScore
	exposed := map[string]bool{}
	for _, tool := range scope.tools() {
		name := tool.Function.Name
		exposed[name] = true
		s, ok := scenarios[name]
		if !ok {
			t.Errorf("tool %s has no scenario", name)
			continue
		}
		score := toolScore{Name: name, Max: 3}
		props, _ := tool.Function.Parameters["properties"].(map[string]any)
		declared := make([]string, 0, len(props))
		for key := range props {
			declared = append(declared, key)
		}
		sort.Strings(declared)
		documented := slices.Sorted(slices.Values(s.Arguments))
		if slices.Equal(declared, documented) {
			score.Points++
		} else {
			score.Lost = append(score.Lost, fmt.Sprintf("schema declares %v, documented %v", declared, documented))
		}
		if _, err := a.readTool(context.Background(), scope, name, string(s.Valid)); err == nil {
			score.Points++
		} else {
			score.Lost = append(score.Lost, fmt.Sprintf("documented arguments %s rejected: %v", s.Valid, err))
		}
		if _, err := a.readTool(context.Background(), scope, name, string(s.Invalid)); err != nil {
			score.Points++
		} else {
			score.Lost = append(score.Lost, fmt.Sprintf("invalid arguments %s accepted", s.Invalid))
		}
		t.Logf("%s %d/%d %v", name, score.Points, score.Max, score.Lost)
		scores = append(scores, score)
	}
	for name := range scenarios {
		if !exposed[name] {
			t.Errorf("scenario %s names no exposed tool", name)
		}
	}
	if out := os.Getenv("SECURE_AGENT_TOOL_SCORES"); out != "" {
		data, err := json.Marshal(scores)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(out, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
