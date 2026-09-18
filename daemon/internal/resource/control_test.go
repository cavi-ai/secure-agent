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

func TestControllerRunsConfiguredInterventionLadderInOrder(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	var actions []ControlAction
	c := NewController(Policy{Mode: ModeTerminate, MaxRSSBytes: 100, Sustain: 10 * time.Second,
		Interventions: []InterventionStep{
			{Action: ActionNotify},
			{Action: ActionLowerPriority, After: 20 * time.Second, Nice: 10},
			{Action: ActionPause, After: 40 * time.Second},
			{Action: ActionTerminate, After: 60 * time.Second},
		}}, func(a ControlAction) error { actions = append(actions, a); return nil })
	snap := controlSnapshot(10, 200, 0)

	c.Observe(snap, now)
	c.Observe(snap, now.Add(10*time.Second))
	c.Observe(snap, now.Add(30*time.Second))
	c.Observe(snap, now.Add(50*time.Second))
	c.Observe(snap, now.Add(70*time.Second))

	if got := actionKinds(actions); fmt.Sprint(got) != fmt.Sprint([]string{"notify", "lower_priority", "pause", "terminate"}) {
		t.Fatalf("actions=%v", got)
	}
	control := c.Snapshot().Sessions[0].Control
	if control.LastAction != ActionTerminate || control.State != StateContained {
		t.Fatalf("control=%+v", control)
	}
}

func TestControllerPromptApprovesCurrentLadderStep(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	var actions []ControlAction
	c := NewController(Policy{Mode: ModePrompt, MaxRSSBytes: 100,
		Interventions: []InterventionStep{{Action: ActionNotify}, {Action: ActionPause, After: time.Second}}},
		func(a ControlAction) error { actions = append(actions, a); return nil })
	snap := controlSnapshot(10, 200, 0)
	c.Observe(snap, now)
	c.Observe(snap, now.Add(time.Second))
	pending := c.Snapshot().Control.Pending
	if len(pending) != 1 || pending[0].Action != ActionPause {
		t.Fatalf("pending=%+v", pending)
	}
	if err := c.Resolve(pending[0].ID, "apply", now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := actionKinds(actions); fmt.Sprint(got) != fmt.Sprint([]string{"notify", "pause"}) {
		t.Fatalf("actions=%v", got)
	}
	if !c.Snapshot().Sessions[0].Control.Paused {
		t.Fatal("approved pause was not reflected in session state")
	}
}

func TestControllerSerializesPendingInterventionExecution(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	started := make(chan struct{})
	release := make(chan struct{})
	calls := 0
	c := NewController(Policy{Mode: ModePrompt, MaxRSSBytes: 100,
		Interventions: []InterventionStep{{Action: ActionPause}}}, func(ControlAction) error {
		calls++
		close(started)
		<-release
		return nil
	})
	c.Observe(controlSnapshot(10, 200, 0), now)
	pending := c.Snapshot().Control.Pending[0]
	first := make(chan error, 1)
	go func() { first <- c.Resolve(pending.ID, "apply", now) }()
	<-started
	if err := c.Resolve(pending.ID, "apply", now); err == nil {
		t.Fatal("duplicate intervention execution was accepted")
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("executor calls=%d", calls)
	}
}

func TestControllerResumePausedSession(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	var actions []ControlAction
	c := NewController(Policy{Mode: ModeTerminate, MaxRSSBytes: 100,
		Interventions: []InterventionStep{{Action: ActionPause}}},
		func(a ControlAction) error { actions = append(actions, a); return nil })
	c.Observe(controlSnapshot(10, 200, 0), now)
	if err := c.Resume("session", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := actionKinds(actions); fmt.Sprint(got) != fmt.Sprint([]string{"pause", "resume"}) {
		t.Fatalf("actions=%v", got)
	}
	if c.Snapshot().Sessions[0].Control.Paused {
		t.Fatal("session remained paused")
	}
}

func TestControllerDoesNotSkipFailedIntervention(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	var actions []ControlAction
	c := NewController(Policy{Mode: ModeTerminate, MaxRSSBytes: 100, Cooldown: time.Minute,
		Interventions: []InterventionStep{{Action: ActionLowerPriority}, {Action: ActionTerminate}}},
		func(a ControlAction) error {
			actions = append(actions, a)
			if a.Kind == string(ActionLowerPriority) {
				return fmt.Errorf("permission denied")
			}
			return nil
		})
	snap := controlSnapshot(10, 200, 0)
	c.Observe(snap, now)
	c.Observe(snap, now.Add(time.Second))
	if got := actionKinds(actions); fmt.Sprint(got) != fmt.Sprint([]string{"lower_priority"}) {
		t.Fatalf("failed step was skipped: %v", got)
	}
	if control := c.Snapshot().Sessions[0].Control; control.State != StateCooldown || control.LastError == "" {
		t.Fatalf("control=%+v", control)
	}
}

func TestControllerMakesPartialPauseRecoverable(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	calls := 0
	c := NewController(Policy{Mode: ModeTerminate, MaxRSSBytes: 100, Cooldown: time.Minute,
		Interventions: []InterventionStep{{Action: ActionPause}}}, func(a ControlAction) error {
		calls++
		if a.Kind == string(ActionPause) {
			return &PartialPauseError{Cause: fmt.Errorf("rollback failed")}
		}
		return nil
	})
	c.Observe(controlSnapshot(10, 200, 0), now)
	control := c.Snapshot().Sessions[0].Control
	if !control.Paused || control.LastError == "" || control.State != StatePaused {
		t.Fatalf("control=%+v", control)
	}
	if err := c.Resume("session", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || c.Snapshot().Sessions[0].Control.Paused {
		t.Fatalf("calls=%d control=%+v", calls, c.Snapshot().Sessions[0].Control)
	}
}

func actionKinds(actions []ControlAction) []string {
	out := make([]string, len(actions))
	for i := range actions {
		out[i] = actions[i].Kind
	}
	return out
}

func controlSnapshot(pid int32, rss uint64, cpu float64) Snapshot {
	start := time.Date(2026, 9, 15, 11, 0, 0, 0, time.UTC)
	return Snapshot{Sessions: []Session{{
		Key: "session", RootPID: pid, RootStartedAt: start, Name: "claude",
		RSSBytes: rss, CPUPercent: cpu, ProcessCount: 1,
		Processes: []Process{{PID: pid, RSSBytes: rss, CPUPercent: cpu}},
	}}}
}

// The budget summary is the fleet heartbeat's "which node is enforcing" line:
// counts of sessions in each budget state plus the mode/enforced flag.
func TestBudgetSummaryCountsStates(t *testing.T) {
	c := NewController(Policy{Mode: ModePrompt, MaxRSSBytes: 1 << 30, Sustain: time.Second}, nil)
	// No sessions: mode + enforced carry, counts are zero.
	b := c.Snapshot().Control.Budget
	if b.Mode != string(ModePrompt) || !b.Enforced {
		t.Fatalf("budget = %+v, want prompt/enforced", b)
	}
	if b.OverBudget != 0 || b.Approval != 0 || b.Contained != 0 || b.Paused != 0 {
		t.Fatalf("empty budget counts = %+v", b)
	}
	// Observe mode with no limits is not "enforced".
	c2 := NewController(Policy{Mode: ModeObserve}, nil)
	if c2.Snapshot().Control.Budget.Enforced {
		t.Fatal("observe with no limits must not read as enforced")
	}
}
