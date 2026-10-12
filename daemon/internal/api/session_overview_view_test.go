package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type memoryOverviewStore struct {
	session      model.Session
	found        bool
	sessionErr   error
	flags        []model.Flag
	flagsErr     error
	sessionID    string
	filter       store.FlagFilter
	findingReads int
}

func (s *memoryOverviewStore) GetSessionResult(id string) (model.Session, bool, error) {
	s.sessionID = id
	return s.session, s.found, s.sessionErr
}

func (s *memoryOverviewStore) QueryFlagsResult(filter store.FlagFilter) ([]model.Flag, error) {
	s.filter = filter
	s.findingReads++
	return s.flags, s.flagsErr
}

func TestSessionOverviewEvidenceBoundedAndSessionScoped(t *testing.T) {
	for _, count := range []int{0, 20, 21} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			at := time.Date(2020, 1, 1, 12, 0, 0, 0, time.UTC)
			s := &memoryOverviewStore{session: model.Session{ID: "session", Status: model.SessionEnded}, found: true}
			for i := range count {
				s.flags = append(s.flags, model.Flag{ID: fmt.Sprint(i), SessionID: "session", Rule: readConnectRule, TS: at, Severity: 3, Acknowledged: true})
			}
			out, err := readSessionOverviewEvidence(s, "session")
			if err != nil || out.Session.ID != "session" || len(out.Findings) != min(count, 20) || out.Truncated != (count > 20) {
				t.Fatalf("bounded evidence: %+v %v", out, err)
			}
			if s.sessionID != "session" || !reflect.DeepEqual(s.filter, store.FlagFilter{SessionID: "session", Limit: 21}) {
				t.Fatalf("session selection widened: %q %+v", s.sessionID, s.filter)
			}
			if count == 0 {
				encoded, _ := json.Marshal(out.Findings)
				if string(encoded) != "[]" {
					t.Fatalf("empty findings became unknown: %s", encoded)
				}
			}
			for i, finding := range out.Findings {
				if finding.ID != fmt.Sprint(i) || !finding.At.Equal(at) || finding.Assessment.ReviewState != "reviewed" || finding.Assessment.ResidualRisk == "" {
					t.Fatalf("retained finding lost order or risk: %+v", finding)
				}
			}
		})
	}
}

func TestSessionOverviewEvidenceReadFailuresAndRecovery(t *testing.T) {
	failed := errors.New("read unavailable")
	for _, phase := range []string{"status", "missing", "findings"} {
		t.Run(phase, func(t *testing.T) {
			s := &memoryOverviewStore{session: model.Session{ID: "session"}, found: true, flags: []model.Flag{{ID: "flag"}}}
			want := errSessionOverviewMissing
			switch phase {
			case "status":
				s.sessionErr, want = failed, errSessionOverviewStatus
			case "missing":
				s.found = false
			case "findings":
				s.flagsErr, want = failed, errSessionOverviewFindings
			}
			out, err := readSessionOverviewEvidence(s, "session")
			if !errors.Is(err, want) || !reflect.DeepEqual(out, sessionOverviewEvidence{}) {
				t.Fatalf("failed read returned usable evidence: %+v %v", out, err)
			}
			if phase != "missing" && !errors.Is(err, failed) {
				t.Fatalf("original read failure lost: %v", err)
			}
			if phase != "findings" && s.findingReads != 0 {
				t.Fatal("findings read after unavailable session identity")
			}
			s.sessionErr, s.flagsErr, s.found = nil, nil, true
			if out, err = readSessionOverviewEvidence(s, "session"); err != nil || len(out.Findings) != 1 || out.Findings[0].ID != "flag" {
				t.Fatalf("new read did not recover: %+v %v", out, err)
			}
		})
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
