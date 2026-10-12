package api

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestSessionOverviewEvidenceTitlesEmptyFindings(t *testing.T) {
	st, err := store.Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	at := time.Date(2020, 1, 1, 12, 0, 0, 0, time.UTC)
	if err := st.UpsertSession(model.Session{ID: "session", StartedAt: at, Status: model.SessionEnded}); err != nil {
		t.Fatal(err)
	}
	out, err := readSessionOverviewEvidence(st, "session")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(out.Findings)
	if err != nil || string(encoded) != "[]" {
		t.Fatalf("empty findings became unknown: %s %v", encoded, err)
	}
	if _, err := st.PutFlag(model.Flag{ID: "flag", SessionID: "session", Rule: readConnectRule, Severity: 3, TS: at}); err != nil {
		t.Fatal(err)
	}
	out, err = readSessionOverviewEvidence(st, "session")
	if err != nil || len(out.Findings) != 1 || out.Findings[0].Title != "Sensitive file read near an outside connection" || out.Findings[0].Assessment.ResidualRisk == "" {
		t.Fatalf("console title: %+v %v", out, err)
	}
}

func TestComposeSessionOverviewKeepsLiveControlsWithTheSession(t *testing.T) {
	start := time.Date(2020, 1, 2, 3, 4, 5, 6, time.UTC)
	evidence := sessionOverviewEvidence{Session: model.Session{
		ID: "session", Status: model.SessionActive, Harness: "claude", RootPID: 40, RootStartedAt: start.Format(time.RFC3339Nano),
	}, Findings: []SessionFinding{}}
	live := sessionOverviewLive{
		Now:             start,
		StatusAvailable: true,
		Pending: []guard.Pending{
			{ID: "other", SessionID: "elsewhere", Tool: "read", Path: "/other"},
			{ID: "guard", SessionID: "session", Tool: "read", Path: "/secret"},
		},
		Coverage: func() []SessionCoverage {
			return []SessionCoverage{{SessionID: "session", Harness: "claude"}, {SessionID: "other", Harness: "codex"}}
		},
		Resources: func() *resource.Snapshot {
			return &resource.Snapshot{ObservedAt: start, Sessions: []resource.Session{
				{Key: "root", RootPID: 40, RootStartedAt: start, Name: "claude", RSSBytes: 1024, ProcessCount: 2},
				{Key: "other", RootPID: 41, RootStartedAt: start, Name: "codex"},
			}}
		},
	}
	out := composeSessionOverview("session", evidence, live)
	if len(out.Requests) != 1 || out.Requests[0].ID != "guard" || out.Coverage == nil || out.Coverage.SessionID != "session" {
		t.Fatalf("live controls leaked or dropped: %+v", out)
	}
	if out.Resources == nil || out.Resources.Key != "root" || out.Resources.RSSBytes != 1024 {
		t.Fatalf("unique resource family lost: %+v", out.Resources)
	}
	live.Resources = func() *resource.Snapshot {
		return &resource.Snapshot{Sessions: []resource.Session{
			{Key: "a", RootPID: 40, RootStartedAt: start, Name: "claude"},
			{Key: "b", RootPID: 40, RootStartedAt: start, Name: "claude"},
		}}
	}
	if ambiguous := composeSessionOverview("session", evidence, live); ambiguous.Resources != nil {
		t.Fatalf("ambiguous resource family attached: %+v", ambiguous.Resources)
	}
	evidence.Session.Status = model.SessionEnded
	coverageReads := 0
	live.Coverage = func() []SessionCoverage {
		coverageReads++
		return []SessionCoverage{{SessionID: "session"}}
	}
	ended := composeSessionOverview("session", evidence, live)
	if ended.Coverage != nil || ended.Resources != nil || coverageReads != 0 || len(ended.Requests) != 1 {
		t.Fatalf("ended session read live snapshots: %+v reads=%d", ended, coverageReads)
	}
	if ended.Requests == nil {
		t.Fatal("requests became unknown")
	}
}
