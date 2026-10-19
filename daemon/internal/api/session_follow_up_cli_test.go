package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestSessionFollowUpCLIIntegration(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "session.db")
	st, err := store.Open(database, "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	targetID := "followup-unique-session"
	siblingID := "sibling-private-session"
	seedFollowUpSession(t, st, targetID, now)
	seedFollowUpSession(t, st, siblingID, now.Add(time.Minute))
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = store.Open(database, "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

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

	socketDir, err := os.MkdirTemp("", "session-follow-up-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(socketDir)
	socket := filepath.Join(socketDir, "api.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	a := New(Deps{Store: st, PeerChecker: NewPeerChecker()})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.ServeListener(ctx, listener) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve API: %v", err)
		}
	}()

	runCLI := func(args ...string) ([]byte, error) {
		t.Helper()
		runCtx, cancelRun := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelRun()
		command := exec.CommandContext(runCtx, cli, args...)
		command.Env = append(os.Environ(), "SECURE_AGENT_SOCK="+socket)
		return command.CombinedOutput()
	}

	output, err := runCLI("session", "followup", "--follow-up", "--json")
	if err != nil {
		t.Fatalf("compiled CLI follow-up: %v\n%s", err, output)
	}
	var follow SessionFollowUp
	if err := json.Unmarshal(output, &follow); err != nil {
		t.Fatalf("follow-up JSON: %v\n%s", err, output)
	}
	if follow.SessionID != targetID || follow.Partial || len(follow.NewerEvidence) != 1 || len(follow.ProcessActions) != 1 || len(follow.ReportedActions) != 1 || len(follow.Permissions) != 1 {
		t.Fatalf("compiled CLI omitted canonical groups or identity: %+v", follow)
	}
	for _, got := range []string{targetID + "-newer-flag", targetID + "-action", targetID + "-incident", targetID + "-scope"} {
		if !strings.Contains(string(output), got) {
			t.Errorf("follow-up JSON missing %q: %s", got, output)
		}
	}
	for _, foreign := range []string{siblingID, siblingID + "-newer-flag", siblingID + "-action", siblingID + "-incident", siblingID + "-scope"} {
		if strings.Contains(string(output), foreign) {
			t.Errorf("follow-up JSON leaked sibling identity %q: %s", foreign, output)
		}
	}

	textOutput, err := runCLI("session", targetID, "--follow-up")
	if err != nil {
		t.Fatalf("compiled CLI text follow-up: %v\n%s", err, textOutput)
	}
	for _, want := range []string{targetID + "-action", "verification not verified", "status unknown (not read)", targetID + "-scope", targetID + "-incident"} {
		if !strings.Contains(string(textOutput), want) {
			t.Errorf("text follow-up missing %q: %s", want, textOutput)
		}
	}

	ordinary, err := runCLI("session", targetID, "--json")
	if err != nil {
		t.Fatalf("ordinary JSON export: %v\n%s", err, ordinary)
	}
	var report store.SessionReport
	if err := json.Unmarshal(ordinary, &report); err != nil || report.Session.ID != targetID {
		t.Fatalf("ordinary export changed or resolved wrong session: %v\n%s", err, ordinary)
	}

	db, err := sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`ALTER TABLE guard_decisions RENAME TO unavailable_guard_decisions`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	partialOutput, err := runCLI("session", "followup", "--follow-up", "--json")
	if err != nil {
		t.Fatalf("partial source follow-up: %v\n%s", err, partialOutput)
	}
	if err := json.Unmarshal(partialOutput, &follow); err != nil {
		t.Fatalf("partial follow-up JSON: %v\n%s", err, partialOutput)
	}
	if follow.SessionID != targetID || !follow.Partial || follow.Sources.Guards.Available || len(follow.Permissions) != 0 || len(follow.NewerEvidence) != 1 || len(follow.ProcessActions) != 1 || len(follow.ReportedActions) != 1 {
		t.Fatalf("source outage was hidden or erased readable follow-up: %+v", follow)
	}
}

func seedFollowUpSession(t *testing.T, st *store.Store, id string, at time.Time) {
	t.Helper()
	rootPID := int32(4242)
	rootStarted := at.Add(-time.Hour)
	endedAt := at.Add(time.Minute)
	if err := st.UpsertSession(model.Session{
		ID: id, Harness: "codex", Workspace: "/synthetic/follow-up", RootPID: rootPID, Confidence: model.ConfHook,
		RootStartedAt: rootStarted.Format(time.RFC3339Nano), Status: model.SessionEnded,
		StartedAt: rootStarted, LastSeenAt: endedAt, EndedAt: &endedAt,
	}); err != nil {
		t.Fatal(err)
	}
	flag := model.Flag{
		ID: id + "-first-flag", SessionID: id, Rule: "sensitive-read-then-connect", Agent: "codex", Workspace: "/synthetic/follow-up", Severity: 3,
		PID: rootPID, TS: at, Evidence: []model.EvidenceItem{
			{Kind: "read", Label: "synthetic-resource", Sub: "sensitive read", PID: rootPID, Exe: "/synthetic/agent", TS: at.Format(time.RFC3339Nano)},
			{Kind: "connect", Label: "203.0.113.8:443", Sub: "egress", PID: rootPID, TS: at.Add(time.Second).Format(time.RFC3339Nano)},
		},
	}
	if _, err := st.PutFlag(flag); err != nil {
		t.Fatal(err)
	}
	page, err := st.ListSessionFindingReviews(id)
	if err != nil || len(page.Reviews) != 1 {
		t.Fatalf("review setup: %+v %v", page, err)
	}
	if _, err := st.DecideFindingReview(model.ReviewDecisionRequest{ID: page.Reviews[0].ID, Revision: page.Reviews[0].Revision, Action: "acknowledge"}); err != nil {
		t.Fatal(err)
	}
	flag.ID = id + "-newer-flag"
	flag.TS = at.Add(time.Second)
	flag.Evidence[0].Sub = "agent tool read"
	flag.Evidence[0].TS = flag.TS.Format(time.RFC3339Nano)
	if _, err := st.PutFlag(flag); err != nil {
		t.Fatal(err)
	}

	intent := model.InterventionReceipt{
		ID: id + "-action", SessionKey: id, RootPID: rootPID, RootStartedAt: rootStarted,
		Revision: 1, Kind: "pause", RequestedAt: at, Status: "requested", Verification: "unknown",
	}
	if reserved, err := st.ReserveIntervention(intent); err != nil || !reserved {
		t.Fatalf("reserve process action: reserved=%v err=%v", reserved, err)
	}
	incident := model.IncidentReport{
		ID: id + "-incident", SessionID: id, Timestamp: at, Rule: "synthetic-rule",
		RotateList: []model.RotateItem{{ID: id + "-step", Name: "Synthetic credential", Action: "Revoke retained credential"}},
	}
	if err := st.PutIncident(incident); err != nil {
		t.Fatal(err)
	}
	stored, err := st.GetIncident(incident.ID)
	if err != nil || stored.Remediation == nil || len(stored.Remediation.Steps) != 1 {
		t.Fatalf("incident remediation setup: %+v %v", stored, err)
	}
	step := stored.Remediation.Steps[0]
	if _, err := st.ReportIncidentRemediation(model.IncidentRemediationRequest{
		ID: incident.ID, StepID: step.ID, ExpectedRevision: stored.Remediation.Revision,
		ExpectedEvidence: stored.Remediation.EvidenceRevision, Status: "reported",
	}); err != nil {
		t.Fatal(err)
	}
	st.PutGuardDecisionForTest(store.GuardDecision{
		ID: id + "-decision", SessionID: id, RuleID: "synthetic-guard", Verdict: "allow", Scope: "exact",
		ScopeIDs: []string{id + "-scope"}, At: at.Format(time.RFC3339Nano),
	})
}
