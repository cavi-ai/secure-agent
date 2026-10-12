package api

import (
	"errors"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type memoryStatusEvidence struct {
	times    map[int32]string
	byRoot   map[int32]model.Session
	flags    []model.Flag
	flagErr  error
	asked    []int32
	filter   store.FlagFilter
	flagRead int
}

func (s *memoryStatusEvidence) LastEventTimes(pids []int32) map[int32]string {
	s.asked = append([]int32(nil), pids...)
	return s.times
}
func (s *memoryStatusEvidence) SessionsByRootPID() map[int32]model.Session { return s.byRoot }
func (s *memoryStatusEvidence) QueryFlags(f store.FlagFilter) ([]model.Flag, error) {
	s.filter = f
	s.flagRead++
	return s.flags, s.flagErr
}

func statusViewAgents() []AgentSummary {
	return []AgentSummary{
		{PID: 20, RootPID: 20},
		{PID: 10, RootPID: 10, Workspace: "/live"},
		{PID: 11, PPID: 10, RootPID: 10},
		{PID: 30, PPID: 1},
	}
}

func TestStatusEvidenceStampsBeforeGroupingAndKeepsLiveFacts(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	st := &memoryStatusEvidence{
		times: map[int32]string{11: "2026-10-12T10:00:00Z", 20: "2026-10-12T09:00:00Z"},
		byRoot: map[int32]model.Session{
			10: {ID: "s-a", Workspace: "/stored", Repo: "repo-a", Branch: "main", Origin: "hook"},
			20: {ID: "s-b", Repo: "repo-b"},
			30: {ID: "s-c", Branch: "feat"},
		},
		flags: make([]model.Flag, 3),
	}
	got := joinStatusEvidence(st, Status{Agents: statusViewAgents()}, now)
	if len(st.asked) != 4 || got.Agents[2].LastSeenAt != "2026-10-12T10:00:00Z" {
		t.Fatalf("last-seen stamp: asked %v, agents %+v", st.asked, got.Agents)
	}
	if len(got.Trees) != 3 || got.Trees[0].Root.PID != 10 || got.Trees[0].LastSeen != "2026-10-12T10:00:00Z" || got.Trees[1].Root.PID != 20 {
		t.Fatalf("trees not ordered by stamped activity: %+v", got.Trees)
	}
	a := got.Trees[0].Root
	if a.SessionID != "s-a" || a.Workspace != "/live" || a.Repo != "repo-a" || a.Branch != "main" || a.Origin != "hook" {
		t.Fatalf("root A joined wrongly: %+v", a)
	}
	if got.Trees[1].Root.SessionID != "s-b" || got.Trees[2].Root.SessionID != "s-c" || got.Trees[2].Root.Branch != "feat" {
		t.Fatalf("roots without a stamped root pid not joined by pid: %+v", got.Trees)
	}
	want := store.FlagFilter{Unacted: true, MinSeverity: 2, Since: "2026-10-11T12:00:00Z", Limit: 500}
	if got.UnactedFlags24h != 3 || st.filter != want {
		t.Fatalf("unacted count %d from %+v, want 3 from %+v", got.UnactedFlags24h, st.filter, want)
	}
}

func TestStatusEvidenceFailedFlagReadKeepsLiveCount(t *testing.T) {
	st := &memoryStatusEvidence{flags: make([]model.Flag, 9), flagErr: errors.New("flags unavailable")}
	got := joinStatusEvidence(st, Status{UnactedFlags24h: 4}, time.Now())
	if got.UnactedFlags24h != 4 || st.flagRead != 1 {
		t.Fatalf("failed flag read changed the count: %d after %d reads", got.UnactedFlags24h, st.flagRead)
	}
	if st.asked != nil || got.Trees == nil || len(got.Trees) != 0 {
		t.Fatalf("no agents: asked %v, trees %+v", st.asked, got.Trees)
	}
}
