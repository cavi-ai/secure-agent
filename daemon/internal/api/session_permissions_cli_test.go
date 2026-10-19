package api

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestSessionFollowUpCLIInspectPermissions(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "session.db")
	st, err := store.Open(database, "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	targetID := "inspect-permissions-session"
	siblingID := "inspect-permissions-sibling"
	seedPermissionInspectionSession(t, st, targetID, now, []string{
		targetID + "-scope", targetID + "-revoked", targetID + "-expired", targetID + "-missing",
	})
	seedPermissionInspectionSession(t, st, siblingID, now.Add(time.Minute), nil)

	targetScopeID := targetID + "-scope"
	revokedID := targetID + "-revoked"
	expiredID := targetID + "-expired"
	missingID := targetID + "-missing"
	sentinelID := siblingID + "-sentinel"
	putFollowUpPermissionScope(t, st, targetScopeID, targetID, "session", now.Add(-time.Minute), time.Time{})
	putFollowUpPermissionScope(t, st, revokedID, targetID, "exact", now.Add(-2*time.Hour), now.Add(2*time.Hour))
	putFollowUpPermissionScope(t, st, sentinelID, siblingID, "session", now.Add(-time.Minute), time.Time{})
	if err := st.RevokeDecisionScope(revokedID); err != nil {
		t.Fatal(err)
	}
	// Insert expired last because a later permission write prunes expired rows.
	putFollowUpPermissionScope(t, st, expiredID, targetID, "exact", now.Add(-2*time.Hour), now.Add(-time.Hour))
	setFollowUpSessionStatus(t, st, targetID, model.SessionEnded, now)
	setFollowUpSessionStatus(t, st, siblingID, model.SessionEnded, now.Add(time.Minute))
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = store.Open(database, "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	before, err := st.ListDecisionScopes()
	if err != nil {
		t.Fatal(err)
	}

	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(dir, "secure-agent")
	buildCtx, cancelBuild := context.WithTimeout(context.Background(), time.Minute)
	defer cancelBuild()
	build := exec.CommandContext(buildCtx, "go", "build", "-o", cli, "./cmd/secure-agent")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, output)
	}

	socketDir, err := os.MkdirTemp("", "session-permissions-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(socketDir)
	socket := filepath.Join(socketDir, "api.sock")
	stopServer := startSessionPermissionsServer(t, st, socket, nil)
	defer stopServer()
	runCLI := func(args ...string) ([]byte, error) {
		t.Helper()
		runCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		command := exec.CommandContext(runCtx, cli, args...)
		command.Env = append(os.Environ(), "SECURE_AGENT_SOCK="+socket)
		return command.CombinedOutput()
	}

	ordinary, err := runCLI("session", targetID, "--follow-up", "--json")
	if err != nil {
		t.Fatalf("ordinary follow-up JSON: %v\n%s", err, ordinary)
	}
	var ordinaryObject map[string]json.RawMessage
	if err := json.Unmarshal(ordinary, &ordinaryObject); err != nil {
		t.Fatalf("ordinary follow-up JSON invalid: %v\n%s", err, ordinary)
	}
	if _, ok := ordinaryObject["permission_inspection"]; ok {
		t.Fatalf("ordinary follow-up changed without opt-in: %s", ordinary)
	}

	output, err := runCLI("session", targetID, "--follow-up", "--inspect-permissions", "--json")
	if err != nil {
		t.Fatalf("compiled CLI permission inspection: %v\n%s", err, output)
	}
	var inspected struct {
		SchemaVersion        int             `json:"schema_version"`
		FollowUp             SessionFollowUp `json:"follow_up"`
		PermissionInspection struct {
			State   string `json:"state"`
			ReadAt  string `json:"read_at"`
			AtLimit bool   `json:"at_limit"`
			Limit   int    `json:"limit"`
			Records []struct {
				ID     string `json:"id"`
				Record *struct {
					model.DecisionScope
					Applicability model.ScopeApplicability `json:"applicability"`
				} `json:"record"`
			} `json:"records"`
		} `json:"permission_inspection"`
	}
	if err := json.Unmarshal(output, &inspected); err != nil {
		t.Fatalf("permission inspection JSON: %v\n%s", err, output)
	}
	pi := inspected.PermissionInspection
	if inspected.SchemaVersion != 1 || inspected.FollowUp.SessionID != targetID || pi.State != "read" || pi.ReadAt == "" || pi.AtLimit || pi.Limit != 10000 {
		t.Fatalf("unexpected inspection envelope: %+v", inspected)
	}
	wantIDs := []string{targetScopeID, revokedID, expiredID, missingID}
	if len(pi.Records) != len(wantIDs) {
		t.Fatalf("inspection records = %+v; want linked IDs %v", pi.Records, wantIDs)
	}
	byID := make(map[string]*struct {
		model.DecisionScope
		Applicability model.ScopeApplicability `json:"applicability"`
	}, len(pi.Records))
	for _, record := range pi.Records {
		byID[record.ID] = record.Record
	}
	for _, id := range wantIDs {
		if _, ok := byID[id]; !ok {
			t.Errorf("inspection omitted linked ID %q", id)
		}
	}
	if byID[missingID] != nil {
		t.Errorf("missing linked record should remain null: %+v", byID[missingID])
	}
	for id, wantLabel := range map[string]string{targetScopeID: "Session permission", revokedID: "Revoked", expiredID: "Expired"} {
		record := byID[id]
		if record == nil || record.ID != id || record.Applicability.Label != wantLabel {
			t.Errorf("permission %s = %+v, want saved record with applicability %q", id, record, wantLabel)
		}
		for _, saved := range before {
			if saved.ID == id && record != nil && !reflect.DeepEqual(record.DecisionScope, saved) {
				t.Errorf("permission %s lifecycle fields changed: got %+v want %+v", id, record.DecisionScope, saved)
			}
		}
	}
	if byID[sentinelID] != nil || strings.Contains(string(output), sentinelID) || strings.Contains(string(output), siblingID) {
		t.Errorf("unrelated permission or sibling identity leaked: %s", output)
	}

	textOutput, err := runCLI("session", targetID, "--follow-up", "--inspect-permissions")
	if err != nil {
		t.Fatalf("compiled CLI text permission inspection: %v\n%s", err, textOutput)
	}
	for _, want := range []string{targetScopeID, revokedID, expiredID, missingID, "Revoked", "Expired"} {
		if !strings.Contains(string(textOutput), want) {
			t.Errorf("text inspection missing %q: %s", want, textOutput)
		}
	}

	stopServer()
	// This injected classifier treats every connected PID as an agent solely
	// for this route-gate test. Kernel peer credentials still come from the
	// platform's real Unix-socket PeerChecker.
	stopAgentClassifiedServer := startSessionPermissionsServer(t, st, socket, func(int32) bool { return true })
	defer stopAgentClassifiedServer()
	if allowed, err := runCLI("session", targetID, "--follow-up", "--json"); err != nil {
		t.Fatalf("NoAgent classification unexpectedly blocked session outcomes: %v\n%s", err, allowed)
	}
	deniedCommand := exec.Command(cli, "session", targetID, "--follow-up", "--inspect-permissions", "--json")
	deniedCommand.Env = append(os.Environ(), "SECURE_AGENT_SOCK="+socket)
	var stdout, stderr strings.Builder
	deniedCommand.Stdout = &stdout
	deniedCommand.Stderr = &stderr
	if err := deniedCommand.Run(); err == nil || stdout.Len() != 0 || !strings.Contains(stderr.String(), "403") {
		t.Fatalf("agent-classified peer should be denied with no JSON stdout: err=%v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	stopAgentClassifiedServer()

	after, err := st.ListDecisionScopes()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("permission inspection mutated saved scopes:\nbefore=%+v\nafter=%+v", before, after)
	}
}

func startSessionPermissionsServer(t *testing.T, st *store.Store, socket string, isAgentPID func(int32) bool) func() {
	t.Helper()
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	a := New(Deps{Store: st, Peers: PeerDeps{Checker: NewPeerChecker(), IsAgentPID: isAgentPID}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.ServeListener(ctx, listener) }()
	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			if err := <-done; err != nil {
				t.Errorf("serve API: %v", err)
			}
		})
	}
}

func setFollowUpSessionStatus(t *testing.T, st *store.Store, id, status string, at time.Time) {
	t.Helper()
	rootPID := int32(4242)
	rootStarted := at.Add(-time.Hour)
	started := rootStarted
	var ended *time.Time
	if status == model.SessionEnded {
		finished := at
		ended = &finished
	}
	if err := st.UpsertSession(model.Session{
		ID: id, Harness: "codex", Workspace: "/synthetic/follow-up", RootPID: rootPID, Confidence: model.ConfHook,
		RootStartedAt: rootStarted.Format(time.RFC3339Nano), Status: status, StartedAt: started,
		LastSeenAt: at, EndedAt: ended,
	}); err != nil {
		t.Fatal(err)
	}
}

func seedPermissionInspectionSession(t *testing.T, st *store.Store, id string, at time.Time, scopeIDs []string) {
	t.Helper()
	rootPID := int32(4242)
	rootStarted := at.Add(-time.Hour)
	if err := st.UpsertSession(model.Session{
		ID: id, Harness: "codex", Workspace: "/synthetic/follow-up", RootPID: rootPID, Confidence: model.ConfHook,
		RootStartedAt: rootStarted.Format(time.RFC3339Nano), Status: model.SessionActive,
		StartedAt: rootStarted, LastSeenAt: at,
	}); err != nil {
		t.Fatal(err)
	}
	if len(scopeIDs) > 0 {
		st.PutGuardDecisionForTest(store.GuardDecision{
			ID: id + "-decision", SessionID: id, RuleID: "synthetic-guard", Verdict: "allow", Scope: "session",
			ScopeIDs: scopeIDs, At: at.Format(time.RFC3339Nano),
		})
	}
}

func putFollowUpPermissionScope(t *testing.T, st *store.Store, id, sessionID, kind string, created, expires time.Time) {
	t.Helper()
	scope := model.DecisionScope{
		ID: id, Kind: kind, Agent: "codex", SessionID: sessionID, Workspace: "/synthetic/follow-up",
		ReaderExe: "/synthetic/agent", RuleID: "synthetic-guard", ResourcePath: "/synthetic/resource",
		Operation: "guard:Read", CreatedAt: created, ExpiresAt: expires, IdentityBasis: "observed-session",
	}
	commit, rollback, err := st.PrepareDecisionScope(context.Background(), scope)
	if err != nil {
		t.Fatalf("prepare permission scope %s: %v", id, err)
	}
	if err := commit(); err != nil {
		rollback()
		t.Fatalf("save permission scope %s: %v", id, err)
	}
}
