package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

const followUpEnvelope = `{"session_id":"session-1","observed_at":"2026-10-18T12:00:00Z","history":{},"follow_up":{"schema_version":1,"session_id":"session-1","observed_at":"2026-10-18T12:00:00Z","partial":false,"sources":{"guards":{"available":true,"at_limit":false,"limit":200},"reviews":{"available":true,"at_limit":false,"limit":100},"incidents":{"available":true,"at_limit":false,"limit":100},"interventions":{"available":true,"at_limit":false,"limit":200}},"newer_evidence":[{"id":"review-1","title":"Sensitive read","revision":2,"decision_revision":1,"evidence_flag_id":"flag-1","evidence_available":true}],"process_actions":[{"id":"action-1","kind":"pause","status":"requested","verification":"unknown","verified_by":"","limits":[]}],"reported_actions":[{"incident_id":"incident-1","step_id":"step-1","title":"Rotate key","action":"Revoke key","newer_evidence":true,"verification":"not_verified"}],"permissions":[{"id":"decision-1","kind":"review","ids":["permission-1","permission-2"],"title":"Decision permissions","status":"unknown"}]}}`

func TestRunSessionFollowUpAcceptsMoreThan1000ReportedActions(t *testing.T) {
	var actions strings.Builder
	actions.WriteByte('[')
	for i := 0; i < 1001; i++ {
		if i > 0 {
			actions.WriteByte(',')
		}
		fmt.Fprintf(&actions, `{"incident_id":"incident-%d","step_id":"step-%04d","title":"Step %d","action":"Review","newer_evidence":false,"verification":"not_verified"}`, i%2, i, i)
	}
	actions.WriteByte(']')
	body := strings.Replace(followUpEnvelope, `[{"incident_id":"incident-1","step_id":"step-1","title":"Rotate key","action":"Revoke key","newer_evidence":true,"verification":"not_verified"}]`, actions.String(), 1)
	client := sessionTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }))
	var out strings.Builder
	if err := runSessionFollowUp(client, "session-1", true, &out); err != nil {
		t.Fatal(err)
	}
	var got struct {
		ReportedActions []struct {
			StepID string `json:"step_id"`
		} `json:"reported_actions"`
	}
	if err := json.Unmarshal([]byte(out.String()), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.ReportedActions) != 1001 || got.ReportedActions[0].StepID != "step-0000" || got.ReportedActions[1000].StepID != "step-1000" {
		t.Fatalf("reported actions count/endpoints = %d/%q/%q", len(got.ReportedActions), got.ReportedActions[0].StepID, got.ReportedActions[1000].StepID)
	}
}

func TestRunSessionFollowUpFormatsAllGroups(t *testing.T) {
	client := sessionTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sessions/session-1/outcomes" {
			t.Errorf("unexpected request: %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		io.WriteString(w, followUpEnvelope)
	}))
	var out strings.Builder
	if err := runSessionFollowUp(client, "session-1", false, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Session session-1", "New evidence", "Sensitive read", "Actions to check", "action-1", "Reported incident actions", "incident-1", "Permissions from decisions", "permission-1", "status unknown", "not verified"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(strings.ToLower(out.String()), "all clear") || strings.Contains(strings.ToLower(out.String()), "task completed") {
		t.Fatalf("output makes an unsupported conclusion:\n%s", out.String())
	}
}

func TestRunSessionFollowUpJSONContainsOnlyValidatedFollowUp(t *testing.T) {
	client := sessionTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, followUpEnvelope) }))
	var out strings.Builder
	if err := runSessionFollowUp(client, "session-1", true, &out); err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out.String()), &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["schema_version"]; !ok || len(got) != 9 {
		t.Fatalf("output was not just follow_up object: %s", out.String())
	}
	if _, ok := got["history"]; ok {
		t.Fatalf("history leaked into output: %s", out.String())
	}
}

func TestRunSessionFollowUpUsesPrefixResolverWithoutReport(t *testing.T) {
	id := "abcdef00-0000-4000-8000-000000000001"
	var requests []string
	client := sessionTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Path)
		switch r.URL.Path {
		case "/sessions/abcdef/outcomes":
			w.WriteHeader(http.StatusNotFound)
		case "/sessions/resolve":
			io.WriteString(w, `[{"id":"`+id+`","harness":"codex"}]`)
		case "/sessions/" + id + "/outcomes":
			io.WriteString(w, strings.ReplaceAll(followUpEnvelope, "session-1", id))
		default:
			t.Errorf("unexpected request: %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	var out strings.Builder
	if err := runSessionFollowUp(client, "abcdef", true, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(requests, ","), "/report") || len(requests) != 3 || requests[1] != "/sessions/resolve" {
		t.Fatalf("requests = %v", requests)
	}
}

func TestRunSessionFollowUpRejectsInvalidPrefixesBeforeResolver(t *testing.T) {
	for _, tc := range []struct{ name, prefix, want string }{
		{"short", "abc", "at least 6"},
		{"invalid UTF-8", string([]byte{0xff, 'a', 'b', 'c', 'd', 'e'}), "valid UTF-8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolverCalled := false
			client := sessionTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/sessions/resolve" {
					resolverCalled = true
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			var out strings.Builder
			err := runSessionFollowUp(client, tc.prefix, true, &out)
			if err == nil || !strings.Contains(err.Error(), tc.want) || resolverCalled || out.Len() != 0 {
				t.Fatalf("error=%v resolverCalled=%v output=%q", err, resolverCalled, out.String())
			}
		})
	}
}

func TestRunSessionFollowUpUnavailableEndpointWritesNoJSON(t *testing.T) {
	client := sessionTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	var out strings.Builder
	err := runSessionFollowUp(client, "session-1", true, &out)
	if err == nil || !strings.Contains(err.Error(), "unavailable (503)") || out.Len() != 0 {
		t.Fatalf("error=%v output=%q", err, out.String())
	}
}

func TestRunSessionFollowUpEmptyAndPartialAreExplicit(t *testing.T) {
	empty := strings.ReplaceAll(followUpEnvelope, `"newer_evidence":[{"id":"review-1","title":"Sensitive read","revision":2,"decision_revision":1,"evidence_flag_id":"flag-1","evidence_available":true}]`, `"newer_evidence":[]`)
	empty = strings.ReplaceAll(empty, `"process_actions":[{"id":"action-1","kind":"pause","status":"requested","verification":"unknown","verified_by":"","limits":[]}]`, `"process_actions":[]`)
	empty = strings.ReplaceAll(empty, `"reported_actions":[{"incident_id":"incident-1","step_id":"step-1","title":"Rotate key","action":"Revoke key","newer_evidence":true,"verification":"not_verified"}]`, `"reported_actions":[]`)
	empty = strings.ReplaceAll(empty, `"permissions":[{"id":"decision-1","kind":"review","ids":["permission-1","permission-2"],"title":"Decision permissions","status":"unknown"}]`, `"permissions":[]`)
	empty = strings.ReplaceAll(empty, `"partial":false`, `"partial":true`)
	empty = strings.ReplaceAll(empty, `"guards":{"available":true,"at_limit":false,"limit":200}`, `"guards":{"available":false,"at_limit":false,"limit":200}`)
	client := sessionTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, empty) }))
	var out strings.Builder
	if err := runSessionFollowUp(client, "session-1", false, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Partial retained result", "Guards unavailable", "No follow-up recorded in retained history"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}
}

func TestRunSessionFollowUpReportsBoundedSource(t *testing.T) {
	body := strings.Replace(followUpEnvelope, `"partial":false`, `"partial":true`, 1)
	body = strings.Replace(body, `"reviews":{"available":true,"at_limit":false,"limit":100}`, `"reviews":{"available":true,"at_limit":true,"limit":100}`, 1)
	client := sessionTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }))
	var out strings.Builder
	if err := runSessionFollowUp(client, "session-1", false, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Reviews reached its 100-row limit") {
		t.Fatalf("bounded-source warning missing:\n%s", out.String())
	}
}

func TestRunSessionFollowUpRejectsUnsupportedAndInvalidResponsesWithoutOutput(t *testing.T) {
	tests := []struct{ name, body, want string }{
		{"unsupported daemon", `{"session_id":"session-1","observed_at":"2026-10-18T12:00:00Z","history":{}}`, "use the console or update daemon"},
		{"malformed JSON", `{`, "invalid session follow-up response"},
		{"foreign session", strings.Replace(followUpEnvelope, `"session_id":"session-1"`, `"session_id":"other"`, 1), "session identity mismatch"},
		{"foreign follow-up identity", strings.Replace(followUpEnvelope, `"schema_version":1,"session_id":"session-1"`, `"schema_version":1,"session_id":"other"`, 1), "session identity mismatch"},
		{"wrong schema", strings.Replace(followUpEnvelope, `"schema_version":1`, `"schema_version":2`, 1), "unsupported session follow-up schema"},
		{"null array", strings.Replace(followUpEnvelope, `"newer_evidence":[{"id":"review-1","title":"Sensitive read","revision":2,"decision_revision":1,"evidence_flag_id":"flag-1","evidence_available":true}]`, `"newer_evidence":null`, 1), "invalid session follow-up"},
		{"partial mismatch", strings.Replace(followUpEnvelope, `"partial":false`, `"partial":true`, 1), "invalid session follow-up"},
		{"permission status", strings.Replace(followUpEnvelope, `"title":"Decision permissions","status":"unknown"`, `"title":"Decision permissions","status":"active"`, 1), "invalid session follow-up"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := sessionTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, tc.body) }))
			var out strings.Builder
			err := runSessionFollowUp(client, "session-1", true, &out)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if out.Len() != 0 {
				t.Fatalf("invalid response produced stdout: %s", out.String())
			}
		})
	}
}

func TestRunSessionFollowUpRejectsUntrustedTerminalControls(t *testing.T) {
	body := strings.Replace(followUpEnvelope, "Sensitive read", "\\u001b[31mSensitive read", 1)
	client := sessionTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }))
	var out strings.Builder
	if err := runSessionFollowUp(client, "session-1", false, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b") || !strings.Contains(out.String(), `\u001B[31m`) {
		t.Fatalf("terminal control was not escaped: %q", out.String())
	}
}
