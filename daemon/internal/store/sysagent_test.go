package store

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestSysAgentMessagesPlansRuns(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()

	u := s.PutSysAgentMessage(model.SysAgentMessage{TS: now, Role: "user", Content: "set up signing", Harness: "codex"})
	a := s.PutSysAgentMessage(model.SysAgentMessage{TS: now, Role: "assistant", Content: "ok",
		Proposal: &model.SysAgentProposal{Title: "Sign commits", Harness: "codex", Mode: "terminal", Task: "t"}})
	if u == 0 || a <= u {
		t.Fatalf("ids = %d, %d", u, a)
	}
	msgs := s.SysAgentMessages(10)
	if len(msgs) != 2 || msgs[0].ID != u || msgs[1].Proposal == nil || msgs[1].Proposal.Title != "Sign commits" {
		t.Fatalf("messages not in chat order with their proposal: %+v", msgs)
	}

	p := model.SysAgentPlan{CreatedAt: now, Source: "agent", MessageID: a, Title: "Sign commits", Harness: "codex",
		Mode: "terminal", Task: "t", Status: "saved", Ready: true, Reason: "computed"}
	pid := s.PutSysAgentPlan(p)
	got, ok := s.GetSysAgentPlan(pid)
	if !ok || got.ID != pid || got.Title != "Sign commits" || got.Ready || got.Reason != "" {
		t.Fatalf("plan = %+v, %v; ready and reason must not be stored", got, ok)
	}
	m, _ := s.GetSysAgentMessage(a)
	m.PlanID = pid
	s.PutSysAgentMessage(m)
	if m, _ = s.GetSysAgentMessage(a); m.PlanID != pid || m.Proposal == nil {
		t.Fatalf("message update lost fields: %+v", m)
	}

	got.Status, got.RunID = "running", 7
	s.PutSysAgentPlan(got)
	if plans := s.SysAgentPlans(10); len(plans) != 1 || plans[0].Status != "running" || plans[0].RunID != 7 {
		t.Fatalf("plans after update = %+v", plans)
	}

	r1 := s.PutSysAgentRun(model.SysAgentRun{PlanID: pid, TS: now, Harness: "codex", Status: "running"})
	fin := now.Add(time.Minute)
	s.PutSysAgentRun(model.SysAgentRun{ID: r1, PlanID: pid, TS: now, FinishedAt: &fin, Harness: "codex", Status: "done"})
	r2 := s.PutSysAgentRun(model.SysAgentRun{PlanID: pid, TS: now, Harness: "codex", Status: "opened"})
	runs := s.SysAgentRuns(10)
	if len(runs) != 2 || runs[0].ID != r2 || runs[1].Status != "done" || runs[1].FinishedAt == nil {
		t.Fatalf("runs = %+v, want newest first with the finished update", runs)
	}

	s.ClearSysAgentMessages()
	if len(s.SysAgentMessages(10)) != 0 || len(s.SysAgentPlans(10)) != 1 {
		t.Fatal("clearing the chat must keep plans")
	}
	if !s.DeleteSysAgentPlan(pid) || s.DeleteSysAgentPlan(pid) {
		t.Fatal("delete must report whether a plan was there")
	}
}
