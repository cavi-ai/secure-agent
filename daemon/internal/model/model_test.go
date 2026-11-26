package model

import (
	"encoding/json"
	"testing"
	"time"
)

// Contract tests: these structs are the wire types the web console and the
// Swift menubar (Models.swift, self-labelled a hand mirror) parse by field
// name. A renamed or re-typed JSON key silently breaks both UIs — these
// tests are the tripwire until the clients are generated from Go (P2).

func assertKeys(t *testing.T, raw []byte, keys ...string) {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			t.Errorf("missing wire key %q in %s", k, raw)
		}
	}
	if len(m) != len(keys) {
		t.Errorf("wire shape drifted: got %d keys %s, want exactly %v", len(m), raw, keys)
	}
}

func TestFlagWireShape(t *testing.T) {
	ts := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	f := Flag{
		ID:        "f1",
		Rule:      "keychain-access",
		Severity:  3,
		TS:        ts,
		PID:       42,
		Agent:     "claude",
		SessionID: "sess-1",
		Evidence:  EvidenceFromStrings("e"),
		Advisor: &AdvisorVerdict{
			Assessment: "suspicious", Confidence: 0.7, Rationale: "r",
			SuggestedAction: "rotate", Model: "m", CreatedAt: ts,
		},
		Acknowledged: true,
	}
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	assertKeys(t, raw, "id", "rule", "severity", "ts", "pid", "agent",
		"session_id", "evidence", "advisor", "acknowledged")

	var back Flag
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.ID != f.ID || back.Advisor == nil || back.Advisor.Assessment != "suspicious" || !back.Acknowledged {
		t.Errorf("round trip mismatch: %+v", back)
	}
}

func TestAdvisorVerdictWireShape(t *testing.T) {
	ts := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	v := AdvisorVerdict{
		Assessment: "benign", Confidence: 0.9, Rationale: "routine",
		SuggestedAction: "none", Model: "qwen3", CreatedAt: ts,
	}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	assertKeys(t, raw, "assessment", "confidence", "rationale",
		"suggested_action", "model", "created_at")
}

func TestIncidentReportWireShape(t *testing.T) {
	ts := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	inc := IncidentReport{
		ID: "i1", FlagID: "f1", PID: 42, Agent: "codex", Timestamp: ts,
		Rule: "proxy-secret-leak", Summary: "s", Risk: RiskCritical,
		TouchedFiles: []string{"~/.aws/credentials"},
		Connections:  []string{"evil.example"},
		RotateList: []RotateItem{{
			ID: "r1", Category: CategoryCloudCreds, Name: "aws",
			Path: "~/.aws/credentials", Risk: RiskHigh,
			Description: "d", Action: "rotate",
		}},
		AdvisorNarrative: "narrative",
	}
	raw, err := json.Marshal(inc)
	if err != nil {
		t.Fatal(err)
	}
	assertKeys(t, raw, "id", "flag_id", "pid", "agent", "timestamp", "rule",
		"summary", "risk", "touched_files", "connections", "rotate_list",
		"advisor_narrative")

	var wire struct {
		Risk       string `json:"risk"`
		RotateList []struct {
			Category string `json:"category"`
			Risk     string `json:"risk"`
		} `json:"rotate_list"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.Risk != "CRITICAL" {
		t.Errorf("incident wire risk = %q, want CRITICAL", wire.Risk)
	}
	if len(wire.RotateList) != 1 || wire.RotateList[0].Risk != "HIGH" ||
		wire.RotateList[0].Category != "CLOUD_CREDENTIALS" {
		t.Errorf("unexpected wire rotation list: %+v", wire.RotateList)
	}
}

func TestNodeStatusWireShape(t *testing.T) {
	ns := NodeStatus{
		Hostname: "mac", OS: "darwin", Arch: "arm64", Agents: 4, Uptime: "1h",
		PostureState: "attention", PostureSummary: "2 items need you",
		NeedsYou: 2,
		Labels:   map[string]string{"env": "prod"},
	}
	raw, err := json.Marshal(ns)
	if err != nil {
		t.Fatal(err)
	}
	assertKeys(t, raw, "hostname", "os", "arch", "agents", "uptime",
		"posture_state", "posture_summary", "needs_you", "labels")
}
