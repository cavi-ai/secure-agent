package resource

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type ControlMode string
type InterventionAction string

const (
	ModeObserve   ControlMode = "observe"
	ModePrompt    ControlMode = "prompt"
	ModeTerminate ControlMode = "terminate"

	ActionNotify        InterventionAction = "notify"
	ActionLowerPriority InterventionAction = "lower_priority"
	ActionPause         InterventionAction = "pause"
	ActionResume        InterventionAction = "resume"
	ActionTerminate     InterventionAction = "terminate"

	StateHealthy    = "healthy"
	StateGrace      = "grace"
	StateExceeded   = "over-budget"
	StateApproval   = "approval-required"
	StateCooldown   = "cooldown"
	StateContained  = "contained"
	StateNotified   = "notified"
	StateIntervened = "intervened"
	StatePaused     = "paused"
)

type InterventionStep struct {
	Action InterventionAction
	After  time.Duration
	Nice   int
}

type Policy struct {
	Mode          ControlMode
	MaxRSSBytes   uint64
	MaxCPUPercent float64
	Sustain       time.Duration
	Cooldown      time.Duration
	Interventions []InterventionStep
}

type WorkspacePolicy struct {
	Path   string
	Policy Policy
}

type PolicySet struct {
	Default            Policy
	WorkspaceOverrides []WorkspacePolicy
}

type Violation struct {
	Metric string  `json:"metric"`
	Actual float64 `json:"actual"`
	Limit  float64 `json:"limit"`
}

type SessionControl struct {
	Mode         ControlMode          `json:"mode"`
	State        string               `json:"state"`
	PolicySource string               `json:"policy_source"`
	PolicyScope  string               `json:"policy_scope,omitempty"`
	BreachSince  *time.Time           `json:"breach_since,omitempty"`
	PendingID    string               `json:"pending_id,omitempty"`
	Violations   []Violation          `json:"violations"`
	LastAction   InterventionAction   `json:"last_action,omitempty"`
	LastError    string               `json:"last_error,omitempty"`
	NextAction   InterventionAction   `json:"next_action,omitempty"`
	NextActionAt *time.Time           `json:"next_action_at,omitempty"`
	Applied      []InterventionAction `json:"applied_actions,omitempty"`
	Paused       bool                 `json:"paused,omitempty"`
}

type PendingAction struct {
	ID         string             `json:"id"`
	SessionKey string             `json:"session_key"`
	RootPID    int32              `json:"root_pid"`
	Name       string             `json:"name"`
	Workspace  string             `json:"workspace,omitempty"`
	CreatedAt  time.Time          `json:"created_at"`
	Violations []Violation        `json:"violations"`
	Action     InterventionAction `json:"action"`
	Nice       int                `json:"nice,omitempty"`
}

type ControlSnapshot struct {
	Mode               ControlMode                `json:"mode"`
	MaxRSSBytes        uint64                     `json:"max_rss_bytes,omitempty"`
	MaxCPUPercent      float64                    `json:"max_cpu_percent,omitempty"`
	SustainSeconds     int64                      `json:"sustain_seconds"`
	CooldownSeconds    int64                      `json:"cooldown_seconds"`
	WorkspaceOverrides []WorkspacePolicySnapshot  `json:"workspace_overrides"`
	Pending            []PendingAction            `json:"pending"`
	Interventions      []InterventionStepSnapshot `json:"interventions,omitempty"`
	// Budget is the one-line fleet summary: how many sessions are over
	// budget, awaiting approval, or contained. Carried in the fleet
	// heartbeat so "which node has a session pinned by a budget" is one
	// number per node, not a full resource fetch per machine.
	Budget BudgetSummary `json:"budget"`
}

// BudgetSummary is the compact budget posture of one node: counts only, no
// session detail — the fleet view answers "which nodes are enforcing".
type BudgetSummary struct {
	// Mode is the machine-default budget mode (observe | prompt | terminate).
	Mode string `json:"mode"`
	// Enforced is true when any RSS or CPU budget is set (nonzero).
	Enforced bool `json:"enforced"`
	// OverBudget / Approval / Contained / Paused count sessions in each state.
	OverBudget int `json:"over_budget"`
	Approval   int `json:"approval"`
	Contained  int `json:"contained"`
	Paused     int `json:"paused"`
}

type InterventionStepSnapshot struct {
	Action       InterventionAction `json:"action"`
	AfterSeconds int64              `json:"after_seconds"`
	Nice         int                `json:"nice,omitempty"`
}

type WorkspacePolicySnapshot struct {
	CwdPrefix       string                     `json:"cwd_prefix"`
	Mode            ControlMode                `json:"mode"`
	MaxRSSBytes     uint64                     `json:"max_rss_bytes,omitempty"`
	MaxCPUPercent   float64                    `json:"max_cpu_percent,omitempty"`
	SustainSeconds  int64                      `json:"sustain_seconds"`
	CooldownSeconds int64                      `json:"cooldown_seconds"`
	Interventions   []InterventionStepSnapshot `json:"interventions,omitempty"`
}

type ControlAction struct {
	Kind            string
	SessionKey      string
	RootPID         int32
	RootStartedAt   time.Time
	TargetPID       int32
	TargetStartedAt time.Time
	Name            string
	Workspace       string
	Violations      []Violation
	Nice            int
}

// PartialPauseError means a pause attempt failed and at least one process
// could not be resumed during rollback. The session remains recoverable through
// the normal resume control.
type PartialPauseError struct{ Cause error }

func (e *PartialPauseError) Error() string { return e.Cause.Error() }
func (e *PartialPauseError) Unwrap() error { return e.Cause }

type sessionState struct {
	breachSince   time.Time
	pendingID     string
	cooldownUntil time.Time
	contained     bool
	applied       map[InterventionAction]bool
	inFlight      InterventionAction
	lastAction    InterventionAction
	lastError     string
	paused        bool
}

type Controller struct {
	mu       sync.Mutex
	policies PolicySet
	states   map[string]*sessionState
	pending  map[string]PendingAction
	latest   Snapshot
	seq      uint64
	execute  func(ControlAction) error
}

func NewController(policy Policy, execute func(ControlAction) error) *Controller {
	return &Controller{policies: normalizedPolicySet(PolicySet{Default: policy}), states: map[string]*sessionState{},
		pending: map[string]PendingAction{}, execute: execute}
}

func normalizedPolicy(p Policy) Policy {
	if p.Mode == "" {
		p.Mode = ModeObserve
	}
	if p.Sustain < 0 {
		p.Sustain = 0
	}
	if p.Cooldown < 0 {
		p.Cooldown = 0
	}
	p.Interventions = append([]InterventionStep(nil), p.Interventions...)
	return p
}

func (c *Controller) SetPolicy(p Policy) {
	c.SetPolicySet(PolicySet{Default: p})
}

// SetPolicySet applies a changed document and reports whether live state was
// reset. Callers use the result to avoid duplicate audit entries when the file
// watcher observes a policy already applied through the API.
func (c *Controller) SetPolicySet(p PolicySet) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	p = normalizedPolicySet(p)
	if equalPolicySet(c.policies, p) {
		return false
	}
	c.policies = p
	c.states = map[string]*sessionState{}
	c.pending = map[string]PendingAction{}
	for i := range c.latest.Sessions {
		c.latest.Sessions[i].Control = nil
	}
	return true
}

func normalizedPolicySet(p PolicySet) PolicySet {
	p.Default = normalizedPolicy(p.Default)
	p.WorkspaceOverrides = append([]WorkspacePolicy(nil), p.WorkspaceOverrides...)
	for i := range p.WorkspaceOverrides {
		p.WorkspaceOverrides[i].Path = filepath.Clean(p.WorkspaceOverrides[i].Path)
		p.WorkspaceOverrides[i].Policy = normalizedPolicy(p.WorkspaceOverrides[i].Policy)
	}
	sort.SliceStable(p.WorkspaceOverrides, func(i, j int) bool {
		return len(p.WorkspaceOverrides[i].Path) > len(p.WorkspaceOverrides[j].Path)
	})
	return p
}

func equalPolicySet(a, b PolicySet) bool {
	if !equalPolicy(a.Default, b.Default) || len(a.WorkspaceOverrides) != len(b.WorkspaceOverrides) {
		return false
	}
	for i := range a.WorkspaceOverrides {
		if a.WorkspaceOverrides[i].Path != b.WorkspaceOverrides[i].Path || !equalPolicy(a.WorkspaceOverrides[i].Policy, b.WorkspaceOverrides[i].Policy) {
			return false
		}
	}
	return true
}

func equalPolicy(a, b Policy) bool {
	if a.Mode != b.Mode || a.MaxRSSBytes != b.MaxRSSBytes || a.MaxCPUPercent != b.MaxCPUPercent || a.Sustain != b.Sustain || a.Cooldown != b.Cooldown || len(a.Interventions) != len(b.Interventions) {
		return false
	}
	for i := range a.Interventions {
		if a.Interventions[i] != b.Interventions[i] {
			return false
		}
	}
	return true
}

func (p PolicySet) forWorkspace(workspace string) (Policy, string) {
	if workspace != "" {
		workspace = filepath.Clean(workspace)
		for _, override := range p.WorkspaceOverrides {
			if workspacePathMatches(workspace, override.Path) {
				return override.Policy, override.Path
			}
		}
	}
	return p.Default, ""
}

func workspacePathMatches(workspace, prefix string) bool {
	if prefix == string(filepath.Separator) {
		return true
	}
	return workspace == prefix || (len(workspace) > len(prefix) && workspace[:len(prefix)] == prefix && workspace[len(prefix)] == filepath.Separator)
}

func (c *Controller) SetTerminator(fn func(ControlAction) error) {
	c.SetExecutor(fn)
}

func (c *Controller) SetExecutor(fn func(ControlAction) error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.execute = fn
}

func (c *Controller) Observe(snapshot Snapshot, now time.Time) {
	c.mu.Lock()
	policies := c.policies
	live := make(map[string]bool, len(snapshot.Sessions))
	type automaticAction struct {
		action   ControlAction
		cooldown time.Duration
	}
	var automatic []automaticAction
	for i := range snapshot.Sessions {
		s := &snapshot.Sessions[i]
		live[s.Key] = true
		policy, scope := policies.forWorkspace(s.Workspace)
		violations := policyViolations(policy, *s)
		source := "default"
		if scope != "" {
			source = "workspace"
		}
		control := &SessionControl{Mode: policy.Mode, State: StateHealthy, PolicySource: source, PolicyScope: scope, Violations: violations}
		s.Control = control
		state := c.states[s.Key]
		if state == nil {
			state = &sessionState{applied: make(map[InterventionAction]bool)}
			c.states[s.Key] = state
		}
		if state.applied == nil {
			state.applied = make(map[InterventionAction]bool)
		}
		populateSessionControl(control, state)
		if len(violations) == 0 {
			delete(c.pending, state.pendingID)
			if state.paused {
				control.State = StatePaused
				continue
			}
			*state = sessionState{applied: make(map[InterventionAction]bool)}
			continue
		}
		if now.Before(state.cooldownUntil) {
			control.State = StateCooldown
			continue
		}
		if state.breachSince.IsZero() {
			state.breachSince = now
		}
		breach := state.breachSince
		control.BreachSince = &breach
		if now.Sub(state.breachSince) < policy.Sustain {
			control.State = StateGrace
			continue
		}
		steps := effectiveInterventions(policy)
		if policy.Mode == ModeObserve || len(steps) == 0 {
			control.State = StateExceeded
			if len(steps) > 0 {
				control.NextAction = steps[0].Action
				due := state.breachSince.Add(policy.Sustain + steps[0].After)
				control.NextActionAt = &due
			}
			continue
		}
		step, found := nextIntervention(steps, state)
		if !found {
			control.State = interventionState(state.lastAction)
			continue
		}
		dueAt := state.breachSince.Add(policy.Sustain + step.After)
		control.NextAction, control.NextActionAt = step.Action, &dueAt
		if now.Before(dueAt) {
			if state.lastAction != "" {
				control.State = interventionState(state.lastAction)
			} else {
				control.State = StateGrace
			}
			continue
		}
		if state.inFlight != "" || state.pendingID != "" {
			if state.pendingID != "" {
				control.State, control.PendingID = StateApproval, state.pendingID
			}
			continue
		}
		targetPID, targetStartedAt := containmentTarget(*s)
		action := ControlAction{Kind: string(step.Action), SessionKey: s.Key, RootPID: s.RootPID,
			RootStartedAt: s.RootStartedAt, TargetPID: targetPID, TargetStartedAt: targetStartedAt,
			Name: s.Name, Workspace: s.Workspace, Nice: step.Nice,
			Violations: append([]Violation(nil), violations...)}
		if policy.Mode == ModePrompt && step.Action != ActionNotify {
			if state.pendingID == "" {
				c.seq++
				state.pendingID = fmt.Sprintf("resource-%d", c.seq)
				c.pending[state.pendingID] = PendingAction{ID: state.pendingID, SessionKey: s.Key,
					RootPID: s.RootPID, Name: s.Name, Workspace: s.Workspace, CreatedAt: now,
					Violations: append([]Violation(nil), violations...), Action: step.Action, Nice: step.Nice}
			}
			control.State, control.PendingID = StateApproval, state.pendingID
			continue
		}
		state.inFlight = step.Action
		control.State = interventionState(step.Action)
		automatic = append(automatic, automaticAction{action: action, cooldown: policy.Cooldown})
	}
	for key, state := range c.states {
		if !live[key] {
			delete(c.pending, state.pendingID)
			delete(c.states, key)
		}
	}
	snapshot.Control = c.controlSnapshotLocked(policies)
	c.latest = cloneSnapshot(snapshot)
	execute := c.execute
	c.mu.Unlock()
	for _, automatic := range automatic {
		var err error
		if execute == nil && automatic.action.Kind != string(ActionNotify) {
			err = fmt.Errorf("resource intervention is unavailable")
		} else if execute != nil {
			err = execute(automatic.action)
		}
		c.mu.Lock()
		c.applyActionResultLocked(automatic.action.SessionKey, InterventionAction(automatic.action.Kind), err, now, automatic.cooldown)
		c.mu.Unlock()
	}
}

func effectiveInterventions(policy Policy) []InterventionStep {
	if len(policy.Interventions) > 0 {
		return policy.Interventions
	}
	if policy.Mode == ModePrompt || policy.Mode == ModeTerminate {
		return []InterventionStep{{Action: ActionTerminate}}
	}
	return nil
}

func nextIntervention(steps []InterventionStep, state *sessionState) (InterventionStep, bool) {
	for _, step := range steps {
		if !state.applied[step.Action] {
			return step, true
		}
	}
	return InterventionStep{}, false
}

func populateSessionControl(control *SessionControl, state *sessionState) {
	control.LastAction, control.LastError, control.Paused = state.lastAction, state.lastError, state.paused
	control.Applied = nil
	for action, applied := range state.applied {
		if applied {
			control.Applied = append(control.Applied, action)
		}
	}
	sort.Slice(control.Applied, func(i, j int) bool { return control.Applied[i] < control.Applied[j] })
}

func interventionState(action InterventionAction) string {
	switch action {
	case ActionNotify:
		return StateNotified
	case ActionPause:
		return StatePaused
	case ActionTerminate:
		return StateContained
	case ActionLowerPriority:
		return StateIntervened
	default:
		return StateExceeded
	}
}

func (c *Controller) applyActionResultLocked(sessionKey string, action InterventionAction, err error, now time.Time, cooldown time.Duration) {
	state := c.states[sessionKey]
	if state == nil {
		return
	}
	state.inFlight = ""
	if err != nil {
		state.lastError = err.Error()
		state.cooldownUntil = now.Add(cooldown)
		var partialPause *PartialPauseError
		if errors.As(err, &partialPause) {
			state.paused = true
			state.lastAction = ActionPause
			c.updateLatestControlLocked(sessionKey, StatePaused, "", state)
		} else {
			c.updateLatestControlLocked(sessionKey, StateCooldown, "", state)
		}
		return
	}
	state.applied[action] = true
	state.lastAction, state.lastError = action, ""
	if action == ActionPause {
		state.paused = true
	}
	if action == ActionResume {
		state.paused = false
	}
	if action == ActionTerminate {
		state.contained = true
	}
	c.updateLatestControlLocked(sessionKey, interventionState(action), "", state)
}

func policyViolations(p Policy, s Session) []Violation {
	var out []Violation
	if p.MaxRSSBytes > 0 && s.RSSBytes > p.MaxRSSBytes {
		out = append(out, Violation{Metric: "rss_bytes", Actual: float64(s.RSSBytes), Limit: float64(p.MaxRSSBytes)})
	}
	if p.MaxCPUPercent > 0 && s.CPUPercent > p.MaxCPUPercent {
		out = append(out, Violation{Metric: "cpu_percent", Actual: s.CPUPercent, Limit: p.MaxCPUPercent})
	}
	return out
}

func (c *Controller) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := cloneSnapshot(c.latest)
	s.Control = c.controlSnapshotLocked(c.policies)
	for i := range s.Sessions {
		if st := c.states[s.Sessions[i].Key]; st != nil && st.pendingID != "" && s.Sessions[i].Control != nil {
			s.Sessions[i].Control.PendingID = st.pendingID
		}
	}
	return s
}

func (c *Controller) controlSnapshotLocked(policies PolicySet) *ControlSnapshot {
	pending := make([]PendingAction, 0, len(c.pending))
	for _, item := range c.pending {
		pending = append(pending, item)
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].CreatedAt.Before(pending[j].CreatedAt) })
	p := policies.Default
	overrides := make([]WorkspacePolicySnapshot, 0, len(policies.WorkspaceOverrides))
	for _, override := range policies.WorkspaceOverrides {
		op := override.Policy
		overrides = append(overrides, WorkspacePolicySnapshot{CwdPrefix: override.Path, Mode: op.Mode,
			MaxRSSBytes: op.MaxRSSBytes, MaxCPUPercent: op.MaxCPUPercent,
			SustainSeconds: int64(op.Sustain.Seconds()), CooldownSeconds: int64(op.Cooldown.Seconds()),
			Interventions: interventionSnapshots(op.Interventions)})
	}
	return &ControlSnapshot{Mode: p.Mode, MaxRSSBytes: p.MaxRSSBytes, MaxCPUPercent: p.MaxCPUPercent,
		SustainSeconds: int64(p.Sustain.Seconds()), CooldownSeconds: int64(p.Cooldown.Seconds()),
		WorkspaceOverrides: overrides, Pending: pending, Interventions: interventionSnapshots(p.Interventions),
		Budget: c.budgetSummaryLocked(policies)}
}

// budgetSummaryLocked counts sessions in each budget state from the latest
// snapshot's per-session control (the derived State field). Counts only — the
// fleet heartbeat carries this so a multi-node view can say "node B has two
// sessions pinned by a budget" without fetching every node's resources.
func (c *Controller) budgetSummaryLocked(policies PolicySet) BudgetSummary {
	b := BudgetSummary{
		Mode:     string(policies.Default.Mode),
		Enforced: policies.Default.MaxRSSBytes > 0 || policies.Default.MaxCPUPercent > 0,
	}
	for i := range c.latest.Sessions {
		ctrl := c.latest.Sessions[i].Control
		if ctrl == nil {
			continue
		}
		switch ctrl.State {
		case StateExceeded:
			b.OverBudget++
		case StateApproval:
			b.Approval++
		case StateContained:
			b.Contained++
		case StatePaused:
			b.Paused++
		}
	}
	return b
}

func interventionSnapshots(steps []InterventionStep) []InterventionStepSnapshot {
	out := make([]InterventionStepSnapshot, 0, len(steps))
	for _, step := range steps {
		out = append(out, InterventionStepSnapshot{Action: step.Action, AfterSeconds: int64(step.After.Seconds()), Nice: step.Nice})
	}
	return out
}

func (c *Controller) Resolve(id, decision string, now time.Time) error {
	c.mu.Lock()
	pending, ok := c.pending[id]
	if !ok {
		c.mu.Unlock()
		return fmt.Errorf("resource action not found")
	}
	if decision != "apply" && decision != string(pending.Action) && decision != "terminate" && decision != "dismiss" {
		c.mu.Unlock()
		return fmt.Errorf("decision must apply the pending action or dismiss")
	}
	state := c.states[pending.SessionKey]
	if state == nil || state.pendingID != id {
		c.mu.Unlock()
		return fmt.Errorf("resource action is no longer active")
	}
	if state.inFlight != "" {
		c.mu.Unlock()
		return fmt.Errorf("resource action is already in progress")
	}
	if decision == "dismiss" {
		delete(c.pending, id)
		state.pendingID = ""
		policy, _ := c.policies.forWorkspace(pending.Workspace)
		state.cooldownUntil = now.Add(policy.Cooldown)
		c.setLatestControlStateLocked(pending.SessionKey, StateCooldown, "")
		c.mu.Unlock()
		return nil
	}
	if decision == "terminate" && pending.Action != ActionTerminate {
		c.mu.Unlock()
		return fmt.Errorf("pending action is %s", pending.Action)
	}
	var action ControlAction
	for _, s := range c.latest.Sessions {
		if s.Key == pending.SessionKey {
			targetPID, targetStartedAt := containmentTarget(s)
			action = ControlAction{Kind: string(pending.Action), SessionKey: s.Key, RootPID: s.RootPID,
				RootStartedAt: s.RootStartedAt, TargetPID: targetPID, TargetStartedAt: targetStartedAt,
				Name: s.Name, Workspace: s.Workspace, Violations: pending.Violations, Nice: pending.Nice}
			break
		}
	}
	state.inFlight = pending.Action
	execute := c.execute
	c.mu.Unlock()
	fail := func(err error) error {
		c.mu.Lock()
		if current := c.states[pending.SessionKey]; current != nil && current.pendingID == id && current.inFlight == pending.Action {
			policy, _ := c.policies.forWorkspace(pending.Workspace)
			c.applyActionResultLocked(pending.SessionKey, pending.Action, err, now, policy.Cooldown)
		}
		c.mu.Unlock()
		return err
	}
	if action.TargetPID == 0 {
		return fail(fmt.Errorf("session is no longer active"))
	}
	if execute == nil {
		return fail(fmt.Errorf("resource intervention is unavailable"))
	}
	if err := execute(action); err != nil {
		return fail(err) // keep the approval pending so the operator can retry
	}
	c.mu.Lock()
	delete(c.pending, id)
	if state := c.states[pending.SessionKey]; state != nil && state.pendingID == id {
		state.pendingID = ""
		policy, _ := c.policies.forWorkspace(pending.Workspace)
		c.applyActionResultLocked(pending.SessionKey, pending.Action, nil, now, policy.Cooldown)
	}
	c.mu.Unlock()
	return nil
}

func (c *Controller) Resume(sessionKey string, now time.Time) error {
	c.mu.Lock()
	state := c.states[sessionKey]
	if state == nil || !state.paused {
		c.mu.Unlock()
		return fmt.Errorf("session is not paused")
	}
	if state.inFlight != "" {
		c.mu.Unlock()
		return fmt.Errorf("resource action is already in progress")
	}
	var action ControlAction
	for _, s := range c.latest.Sessions {
		if s.Key == sessionKey {
			targetPID, targetStartedAt := containmentTarget(s)
			action = ControlAction{Kind: string(ActionResume), SessionKey: s.Key, RootPID: s.RootPID,
				RootStartedAt: s.RootStartedAt, TargetPID: targetPID, TargetStartedAt: targetStartedAt,
				Name: s.Name, Workspace: s.Workspace}
			break
		}
	}
	state.inFlight = ActionResume
	execute := c.execute
	c.mu.Unlock()
	fail := func(err error) error {
		c.mu.Lock()
		if current := c.states[sessionKey]; current != nil && current.inFlight == ActionResume {
			policy, _ := c.policies.forWorkspace(action.Workspace)
			c.applyActionResultLocked(sessionKey, ActionResume, err, now, policy.Cooldown)
		}
		c.mu.Unlock()
		return err
	}
	if action.TargetPID == 0 {
		return fail(fmt.Errorf("session is no longer active"))
	}
	if execute == nil {
		return fail(fmt.Errorf("resource intervention is unavailable"))
	}
	if err := execute(action); err != nil {
		return fail(err)
	}
	c.mu.Lock()
	if state := c.states[sessionKey]; state != nil {
		if state.pendingID != "" {
			delete(c.pending, state.pendingID)
			state.pendingID = ""
		}
		policy, _ := c.policies.forWorkspace(action.Workspace)
		state.cooldownUntil = now.Add(policy.Cooldown)
		c.applyActionResultLocked(sessionKey, ActionResume, nil, now, policy.Cooldown)
		c.updateLatestControlLocked(sessionKey, StateCooldown, "", state)
	}
	c.mu.Unlock()
	return nil
}

func containmentTarget(s Session) (int32, time.Time) {
	for _, process := range s.Processes {
		if process.PID == s.RootPID {
			return process.PID, process.StartedAt
		}
	}
	if len(s.Processes) > 0 {
		return s.Processes[0].PID, s.Processes[0].StartedAt
	}
	return s.RootPID, s.RootStartedAt
}

func (c *Controller) setLatestControlStateLocked(sessionKey, state, pendingID string) {
	c.updateLatestControlLocked(sessionKey, state, pendingID, c.states[sessionKey])
}

func (c *Controller) updateLatestControlLocked(sessionKey, controlState, pendingID string, state *sessionState) {
	for i := range c.latest.Sessions {
		if c.latest.Sessions[i].Key != sessionKey || c.latest.Sessions[i].Control == nil {
			continue
		}
		c.latest.Sessions[i].Control.State = controlState
		c.latest.Sessions[i].Control.PendingID = pendingID
		if controlState != StateCooldown && controlState != StateApproval {
			c.latest.Sessions[i].Control.NextAction = ""
			c.latest.Sessions[i].Control.NextActionAt = nil
		}
		if state != nil {
			populateSessionControl(c.latest.Sessions[i].Control, state)
		}
		return
	}
}
