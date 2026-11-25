package sysagent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"
	"unicode/utf8"

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

// Scores every tool replyScope.tools exposes. Its advertised schema must match
// the documented contract and accept the valid example. Agent.readTool is
// scored separately on valid and invalid examples. Tools and scenarios must
// match one to one. SECURE_AGENT_TOOL_SCORES receives the scores as JSON.
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
	idsByTool := map[string][]string{
		"inspect_skill":            skillOrder,
		"inspect_finding":          {doc.Finding.ID},
		"inspect_session_activity": {doc.Finding.SessionID},
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
		if err := checkToolScenarioSchema(s, tool.Function.Parameters, idsByTool[name]); err == nil {
			score.Points++
		} else {
			score.Lost = append(score.Lost, err.Error())
			t.Errorf("tool %s: %v", name, err)
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

func checkToolScenarioSchema(s toolScenario, parameters map[string]any, ids []string) error {
	var valid map[string]*string
	if err := json.Unmarshal(s.Valid, &valid); err != nil || valid == nil {
		return fmt.Errorf("valid arguments must be an object of strings: %s", s.Valid)
	}
	properties := map[string]any{}
	want := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	for _, name := range s.Arguments {
		value, present := valid[name]
		if present && value == nil {
			return fmt.Errorf("valid argument %q must be a string", name)
		}
		switch name {
		case "id":
			properties[name] = map[string]any{"type": "string", "enum": ids}
			want["required"] = []string{name}
			if !present || !slices.Contains(ids, *value) {
				return fmt.Errorf("valid arguments must contain an id from %v: %s", ids, s.Valid)
			}
		case "query":
			const maxLength = 128
			properties[name] = map[string]any{"type": "string", "maxLength": maxLength}
			if present && utf8.RuneCountInString(*value) > maxLength {
				return fmt.Errorf("valid query exceeds %d characters", maxLength)
			}
		default:
			return fmt.Errorf("undocumented schema constraints for argument %q", name)
		}
		delete(valid, name)
	}
	if len(valid) != 0 {
		return fmt.Errorf("valid arguments contain extra properties: %s", s.Valid)
	}
	if !reflect.DeepEqual(parameters, want) {
		return fmt.Errorf("advertised schema is %v, want %v", parameters, want)
	}
	return nil
}
