package resource

import (
	"fmt"
	"testing"
	"time"
)

func TestControllerObserveRequiresSustainedBreach(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	var actions []ControlAction
	c := NewController(Policy{Mode: ModeTerminate, MaxRSSBytes: 100, Sustain: 30 * time.Second},
		func(a ControlAction) error { actions = append(actions, a); return nil })
	snap := controlSnapshot(10, 150, 0)

	c.Observe(snap, now)
	if got := c.Snapshot().Sessions[0].Control.State; got != StateGrace {
		t.Fatalf("state=%q want %q", got, StateGrace)
	}
	c.Observe(snap, now.Add(29*time.Second))
	if len(actions) != 0 {
		t.Fatalf("acted before grace elapsed: %+v", actions)
	}
	c.Observe(snap, now.Add(30*time.Second))
	if len(actions) != 1 || actions[0].RootPID != 10 {
		t.Fatalf("actions=%+v want one root 10", actions)
	}
}

func TestControllerPromptRequiresExplicitResolution(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	var actions []ControlAction
	c := NewController(Policy{Mode: ModePrompt, MaxCPUPercent: 100},
		func(a ControlAction) error { actions = append(actions, a); return nil })
	c.Observe(controlSnapshot(10, 0, 150), now)
	snap := c.Snapshot()
	if len(snap.Control.Pending) != 1 || snap.Sessions[0].Control.State != StateApproval {
		t.Fatalf("control=%+v session=%+v", snap.Control, snap.Sessions[0].Control)
	}
	if err := c.Resolve(snap.Control.Pending[0].ID, "terminate", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 {
		t.Fatalf("actions=%d want 1", len(actions))
	}
	if len(c.Snapshot().Control.Pending) != 0 {
		t.Fatal("resolved action remained pending")
	}
}

func TestControllerObserveModeNeverContains(t *testing.T) {
	var actions []ControlAction
	c := NewController(Policy{Mode: ModeObserve, MaxRSSBytes: 100},
		func(a ControlAction) error { actions = append(actions, a); return nil })
	c.Observe(controlSnapshot(10, 200, 0), time.Now())
	if len(actions) != 0 {
		t.Fatal("observe mode contained a session")
	}
	if got := c.Snapshot().Sessions[0].Control.State; got != StateExceeded {
		t.Fatalf("state=%q want %q", got, StateExceeded)
	}
}

func TestControllerSelectsLongestWorkspacePolicy(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	c := NewController(Policy{Mode: ModeObserve, MaxRSSBytes: 100}, nil)
	c.SetPolicySet(PolicySet{
		Default: Policy{Mode: ModeObserve, MaxRSSBytes: 100},
		WorkspaceOverrides: []WorkspacePolicy{
			{Path: "/work", Policy: Policy{Mode: ModePrompt, MaxRSSBytes: 200}},
			{Path: "/work/critical", Policy: Policy{Mode: ModeTerminate, MaxRSSBytes: 300}},
		},
	})
	snapshot := Snapshot{Sessions: []Session{
		{Key: "deep", Workspace: "/work/critical/service", RootPID: 10, RSSBytes: 350},
		{Key: "parent", Workspace: "/work/other", RootPID: 11, RSSBytes: 250},
		{Key: "boundary", Workspace: "/worker", RootPID: 12, RSSBytes: 150},
	}}
	c.Observe(snapshot, now)
	got := c.Snapshot().Sessions
	if got[0].Control.PolicySource != "workspace" || got[0].Control.PolicyScope != "/work/critical" || got[0].Control.Mode != ModeTerminate {
		t.Fatalf("deep control=%+v", got[0].Control)
	}
	if got[1].Control.PolicyScope != "/work" || got[1].Control.Mode != ModePrompt {
		t.Fatalf("parent control=%+v", got[1].Control)
	}
	if got[2].Control.PolicySource != "default" || got[2].Control.PolicyScope != "" || got[2].Control.Mode != ModeObserve {
		t.Fatalf("boundary control=%+v", got[2].Control)
	}
	if len(c.Snapshot().Control.WorkspaceOverrides) != 2 {
		t.Fatalf("overrides=%+v", c.Snapshot().Control.WorkspaceOverrides)
	}
}

func TestControllerDismissAddsCooldown(t *testing.T) {
	now := time.Now()
	c := NewController(Policy{Mode: ModePrompt, MaxRSSBytes: 100, Cooldown: time.Minute}, nil)
	c.Observe(controlSnapshot(10, 200, 0), now)
	id := c.Snapshot().Control.Pending[0].ID
	if err := c.Resolve(id, "dismiss", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	c.Observe(controlSnapshot(10, 200, 0), now.Add(30*time.Second))
	if len(c.Snapshot().Control.Pending) != 0 {
		t.Fatal("dismissed breach reprompted during cooldown")
	}
	if got := c.Snapshot().Sessions[0].Control.State; got != StateCooldown {
		t.Fatalf("state=%q want %q after dismissal", got, StateCooldown)
	}
	if got := c.Snapshot().Sessions[0].Control.PendingID; got != "" {
		t.Fatalf("pending id remained visible after dismissal: %q", got)
	}
}

func TestControllerFailedPromptContainmentRemainsPending(t *testing.T) {
	now := time.Now()
	c := NewController(Policy{Mode: ModePrompt, MaxRSSBytes: 100},
		func(ControlAction) error { return fmt.Errorf("signal refused") })
	c.Observe(controlSnapshot(10, 200, 0), now)
	id := c.Snapshot().Control.Pending[0].ID
	if err := c.Resolve(id, "terminate", now); err == nil {
		t.Fatal("failed terminator reported success")
	}
	if len(c.Snapshot().Control.Pending) != 1 {
		t.Fatal("failed containment discarded the operator approval")
	}
}

func TestControllerTargetsLiveMemberForOrphanOnlySession(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 123456789, time.UTC)
	var action ControlAction
	c := NewController(Policy{Mode: ModeTerminate, MaxRSSBytes: 100}, func(a ControlAction) error {
		action = a
		return nil
	})
	c.Observe(Snapshot{Sessions: []Session{{
		Key: "orphan-family", RootPID: 10, Name: "claude", RSSBytes: 200,
		Processes: []Process{{PID: 11, StartedAt: now, RSSBytes: 200, IsOrphan: true}},
	}}}, now)
	if action.RootPID != 10 || action.TargetPID != 11 || !action.TargetStartedAt.Equal(now) {
		t.Fatalf("action=%+v want family root 10 and live target 11 at %v", action, now)
	}
}

func controlSnapshot(pid int32, rss uint64, cpu float64) Snapshot {
	start := time.Date(2026, 9, 15, 11, 0, 0, 0, time.UTC)
	return Snapshot{Sessions: []Session{{
		Key: "session", RootPID: pid, RootStartedAt: start, Name: "claude",
		RSSBytes: rss, CPUPercent: cpu, ProcessCount: 1,
		Processes: []Process{{PID: pid, RSSBytes: rss, CPUPercent: cpu}},
	}}}
}
