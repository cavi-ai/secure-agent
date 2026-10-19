package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const followUpEnvelope = `{"session_id":"session-1","observed_at":"2026-10-18T12:00:00Z","history":{},"follow_up":{"schema_version":1,"session_id":"session-1","observed_at":"2026-10-18T12:00:00Z","partial":false,"sources":{"guards":{"available":true,"at_limit":false,"limit":200},"reviews":{"available":true,"at_limit":false,"limit":100},"incidents":{"available":true,"at_limit":false,"limit":100},"interventions":{"available":true,"at_limit":false,"limit":200}},"newer_evidence":[{"id":"review-1","title":"Sensitive read","revision":2,"decision_revision":1,"evidence_flag_id":"flag-1","evidence_available":true}],"process_actions":[{"id":"action-1","kind":"pause","status":"requested","verification":"unknown","verified_by":"","limits":[]}],"reported_actions":[{"incident_id":"incident-1","step_id":"step-1","title":"Rotate key","action":"Revoke key","newer_evidence":true,"verification":"not_verified"}],"permissions":[{"id":"decision-1","kind":"review","ids":["permission-1","permission-2"],"title":"Decision permissions","status":"unknown"}]}}`

func TestSessionCLIHelperProcess(t *testing.T) {
	if os.Getenv("SECURE_AGENT_CLI_HELPER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"secure-agent"}, os.Args[i+1:]...)
			handleSession(unixClient(getSocketPath()))
			os.Exit(0)
		}
	}
	os.Exit(2)
}

func TestSessionCLIInspectPermissionsReadsLinkedRecords(t *testing.T) {
	socketFile, err := os.CreateTemp("/tmp", "sa-*.sock")
	if err != nil {
		t.Fatal(err)
	}
	sock := socketFile.Name()
	socketFile.Close()
	os.Remove(sock)
	t.Cleanup(func() { os.Remove(sock) })
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	paths := make(chan string, 4)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths <- r.URL.Path
		switch r.URL.Path {
		case "/sessions/session-1/outcomes":
			io.WriteString(w, followUpEnvelope)
		case "/decision-scopes":
			io.WriteString(w, `[]`)
		default:
			http.NotFound(w, r)
		}
	})}
	go server.Serve(listener)
	defer server.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSessionCLIHelperProcess$", "--", "session", "session-1", "--follow-up", "--inspect-permissions", "--json")
	cmd.Env = append(os.Environ(), "SECURE_AGENT_CLI_HELPER=1", "SECURE_AGENT_SOCK="+sock)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI failed: %v\n%s", err, output)
	}
	requestedScopes := false
	for len(paths) > 0 {
		if <-paths == "/decision-scopes" {
			requestedScopes = true
		}
	}
	if !requestedScopes {
		t.Fatalf("CLI did not read linked permission records; output=%s", output)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(output, &got); err != nil {
		t.Fatalf("CLI output is not JSON: %v\n%s", err, output)
	}
	if _, ok := got["permission_inspection"]; !ok {
		t.Fatalf("CLI JSON omitted permission_inspection: %s", output)
	}
}

func TestSessionCLIInspectPermissionsRequiresFollowUp(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestSessionCLIHelperProcess$", "--", "session", "session-1", "--inspect-permissions")
	cmd.Env = append(os.Environ(), "SECURE_AGENT_CLI_HELPER=1", "SECURE_AGENT_SOCK=/tmp/no-such-secure-agent.sock")
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err == nil || stdout.Len() != 0 || !strings.Contains(stderr.String(), "requires --follow-up") || !strings.Contains(stderr.String(), "usage: secure-agent session") {
		t.Fatalf("exit=%v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
}

func TestRunSessionFollowUpInspectionSelectsOnlyLinkedPermissionIDs(t *testing.T) {
	body := strings.Replace(followUpEnvelope,
		`"permissions":[{"id":"decision-1","kind":"review","ids":["permission-1","permission-2"],"title":"Decision permissions","status":"unknown"}]`,
		`"permissions":[{"id":"decision-1","kind":"review","ids":["permission-1","permission-2"],"title":"Decision permissions","status":"unknown"},{"id":"decision-2","kind":"guard","ids":["permission-1","permission-3"],"title":"Guard decision","status":"unknown"}]`, 1)
	created := "2026-10-18T10:00:00Z"
	otherSession := "origin-session"
	applicability := &savedPermissionApplicability{Label: "Timed permission", Revoke: boolPointer(true)}
	linked := savedPermissionRecord{ID: "permission-1", Kind: "exact", Agent: "claude\x1b[31m", SessionID: &otherSession, RuleID: "rule-1", ResourcePath: "/repo/private.txt", Operation: "guard:read", CreatedAt: created, Applicability: applicability}
	unrelated := savedPermissionRecord{ID: "unrelated", Kind: "session", Agent: "codex", RuleID: "rule-2", ResourcePath: "/repo/other.txt", Operation: "guard:write", CreatedAt: created}
	scopeJSON, _ := json.Marshal([]savedPermissionRecord{linked, unrelated})
	client := sessionTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sessions/session-1/outcomes":
			io.WriteString(w, body)
		case "/decision-scopes":
			w.Write(scopeJSON)
		default:
			t.Errorf("unexpected request: %s", r.URL)
			http.NotFound(w, r)
		}
	}))
	var out strings.Builder
	if err := runSessionFollowUpInspection(client, "session-1", true, &out); err != nil {
		t.Fatal(err)
	}
	var got sessionFollowUpInspection
	if err := json.Unmarshal([]byte(out.String()), &got); err != nil {
		t.Fatal(err)
	}
	inspection := got.PermissionInspection
	if inspection.State != "read" || inspection.ReadAt == nil || inspection.ReadAt.Location() != time.UTC || inspection.AtLimit || inspection.Limit != maxDecisionScopeRows {
		t.Fatalf("inspection metadata = %+v", inspection)
	}
	if len(inspection.Records) != 3 || inspection.Records[0].ID != "permission-1" || inspection.Records[0].Record == nil || inspection.Records[0].Record.SessionID == nil || *inspection.Records[0].Record.SessionID != otherSession {
		t.Fatalf("linked exact permission from another session was not retained: %+v", inspection.Records)
	}
	if inspection.Records[1].ID != "permission-2" || inspection.Records[1].Record != nil || inspection.Records[2].ID != "permission-3" || inspection.Records[2].Record != nil {
		t.Fatalf("missing linked records were not kept unknown: %+v", inspection.Records)
	}
	if inspection.Records[0].Record.Applicability == nil || inspection.Records[0].Record.Applicability.Label != "Timed permission" {
		t.Fatalf("saved applicability missing: %+v", inspection.Records[0].Record)
	}
	var textOut strings.Builder
	if err := runSessionFollowUpInspection(client, "session-1", false, &textOut); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(textOut.String(), "\x1b") || !strings.Contains(textOut.String(), `\u001B[31m`) || !strings.Contains(textOut.String(), "Timed permission") || !strings.Contains(textOut.String(), "does not establish effective access") || !strings.Contains(textOut.String(), "current status unknown (record unavailable)") {
		t.Fatalf("permission text did not escape metadata or show qualified applicability: %q", textOut.String())
	}
}

func TestRunSessionFollowUpInspectionSkipsReadWithoutLinkedIDs(t *testing.T) {
	body := strings.Replace(followUpEnvelope, `"permissions":[{"id":"decision-1","kind":"review","ids":["permission-1","permission-2"],"title":"Decision permissions","status":"unknown"}]`, `"permissions":[]`, 1)
	permissionRead := false
	client := sessionTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/decision-scopes" {
			permissionRead = true
			http.Error(w, "unexpected", http.StatusInternalServerError)
			return
		}
		io.WriteString(w, body)
	}))
	var out strings.Builder
	if err := runSessionFollowUpInspection(client, "session-1", true, &out); err != nil {
		t.Fatal(err)
	}
	var got sessionFollowUpInspection
	if err := json.Unmarshal([]byte(out.String()), &got); err != nil {
		t.Fatal(err)
	}
	if permissionRead || got.PermissionInspection.State != "not_needed" || got.PermissionInspection.ReadAt != nil || got.PermissionInspection.Records == nil || len(got.PermissionInspection.Records) != 0 {
		t.Fatalf("empty linked IDs triggered or misreported a permission read: read=%v inspection=%+v", permissionRead, got.PermissionInspection)
	}
}

func TestRunSessionFollowUpInspectionRejectsInvalidPermissionReadsWithoutOutput(t *testing.T) {
	validRecord := `{"id":"permission-1","kind":"session","agent":"codex","rule_id":"r1","resource_path":"/repo/x","operation":"guard:read","created_at":"2026-10-18T10:00:00Z"}`
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{"forbidden", http.StatusForbidden, "forbidden"},
		{"server error", http.StatusServiceUnavailable, "unavailable"},
		{"non-array", http.StatusOK, `null`},
		{"malformed", http.StatusOK, `{`},
		{"duplicate ids", http.StatusOK, `[` + validRecord + `,` + validRecord + `]`},
		{"missing required field", http.StatusOK, `[{"id":"permission-1"}]`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := sessionTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/sessions/session-1/outcomes" {
					io.WriteString(w, followUpEnvelope)
					return
				}
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			var out strings.Builder
			err := runSessionFollowUpInspection(client, "session-1", true, &out)
			if err == nil || out.Len() != 0 {
				t.Fatalf("error=%v stdout=%q", err, out.String())
			}
		})
	}
}

func TestRunSessionFollowUpInspectionAtLimitAndMissingApplicability(t *testing.T) {
	rows := make([]savedPermissionRecord, maxDecisionScopeRows)
	for i := range rows {
		rows[i] = savedPermissionRecord{ID: fmt.Sprintf("scope-%d", i), Kind: "session", Agent: "codex", RuleID: "r1", ResourcePath: "/repo/x", Operation: "guard:read", CreatedAt: "2026-10-18T10:00:00Z"}
	}
	rows[0].ID = "permission-1"
	scopeJSON, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	client := sessionTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sessions/session-1/outcomes" {
			io.WriteString(w, followUpEnvelope)
			return
		}
		w.Write(scopeJSON)
	}))
	var out strings.Builder
	if err := runSessionFollowUpInspection(client, "session-1", true, &out); err != nil {
		t.Fatal(err)
	}
	var got sessionFollowUpInspection
	if err := json.Unmarshal([]byte(out.String()), &got); err != nil {
		t.Fatal(err)
	}
	if !got.PermissionInspection.AtLimit || len(got.PermissionInspection.Records) != 2 || got.PermissionInspection.Records[0].Record == nil || got.PermissionInspection.Records[0].Record.Applicability != nil || got.PermissionInspection.Records[1].Record != nil {
		t.Fatalf("at-limit or unknown applicability was lost: %+v", got.PermissionInspection)
	}
	var textOut strings.Builder
	if err := renderPermissionInspection(&textOut, got.PermissionInspection); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(textOut.String(), "Applicability unknown") || !strings.Contains(textOut.String(), "reached its 10000-record limit") || !strings.Contains(textOut.String(), "current status unknown") {
		t.Fatalf("unknown and capped states were not explicit: %s", textOut.String())
	}
}

func TestRunSessionFollowUpInspectionRejectsMoreThanLimit(t *testing.T) {
	rows := make([]savedPermissionRecord, maxDecisionScopeRows+1)
	for i := range rows {
		rows[i] = savedPermissionRecord{ID: fmt.Sprintf("scope-%d", i), Kind: "session", Agent: "codex", RuleID: "r1", ResourcePath: "/repo/x", Operation: "guard:read", CreatedAt: "2026-10-18T10:00:00Z"}
	}
	scopeJSON, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	client := sessionTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sessions/session-1/outcomes" {
			io.WriteString(w, followUpEnvelope)
			return
		}
		w.Write(scopeJSON)
	}))
	var out strings.Builder
	err = runSessionFollowUpInspection(client, "session-1", true, &out)
	if err == nil || !strings.Contains(err.Error(), "exceeds 10000") || out.Len() != 0 {
		t.Fatalf("error=%v stdout=%q", err, out.String())
	}
}

func boolPointer(value bool) *bool { return &value }

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
