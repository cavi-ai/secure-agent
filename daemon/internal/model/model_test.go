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
		Evidence:  []string{"e"},
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

	var back IncidentReport
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.Risk != RiskCritical || len(back.RotateList) != 1 || back.RotateList[0].Category != CategoryCloudCreds {
		t.Errorf("round trip mismatch: %+v", back)
	}
}

func TestRiskAndCategoryValuesAreStable(t *testing.T) {
	// The Swift UI switches on these strings; a rename breaks rendering.
	risks := map[RiskLevel]string{
		RiskCritical: "CRITICAL", RiskHigh: "HIGH", RiskMedium: "MEDIUM", RiskLow: "LOW",
	}
	for got, want := range risks {
		if string(got) != want {
			t.Errorf("RiskLevel %q != %q", got, want)
		}
	}
	cats := map[SecretCategory]string{
		CategoryKeychain: "KEYCHAIN", CategoryCloudCreds: "CLOUD_CREDENTIALS",
		CategorySSHKeys: "SSH_KEYS", CategoryEnvSecrets: "ENV_SECRETS",
		CategorySourceControl: "SOURCE_CONTROL", CategorySystemConfig: "SYSTEM_CONFIG",
		CategoryOther: "OTHER",
	}
	for got, want := range cats {
		if string(got) != want {
			t.Errorf("SecretCategory %q != %q", got, want)
		}
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
