package resource

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

type ControlMode string

const (
	ModeObserve   ControlMode = "observe"
	ModePrompt    ControlMode = "prompt"
	ModeTerminate ControlMode = "terminate"

	StateHealthy   = "healthy"
	StateGrace     = "grace"
	StateExceeded  = "over-budget"
	StateApproval  = "approval-required"
	StateCooldown  = "cooldown"
	StateContained = "contained"
)

type Policy struct {
	Mode          ControlMode
	MaxRSSBytes   uint64
	MaxCPUPercent float64
	Sustain       time.Duration
	Cooldown      time.Duration
}

type Violation struct {
	Metric string  `json:"metric"`
	Actual float64 `json:"actual"`
	Limit  float64 `json:"limit"`
}

type SessionControl struct {
	Mode        ControlMode `json:"mode"`
	State       string      `json:"state"`
	BreachSince *time.Time  `json:"breach_since,omitempty"`
	PendingID   string      `json:"pending_id,omitempty"`
	Violations  []Violation `json:"violations"`
}

type PendingAction struct {
	ID         string      `json:"id"`
	SessionKey string      `json:"session_key"`
	RootPID    int32       `json:"root_pid"`
	Name       string      `json:"name"`
	Workspace  string      `json:"workspace,omitempty"`
	CreatedAt  time.Time   `json:"created_at"`
	Violations []Violation `json:"violations"`
}

type ControlSnapshot struct {
	Mode            ControlMode     `json:"mode"`
	MaxRSSBytes     uint64          `json:"max_rss_bytes,omitempty"`
	MaxCPUPercent   float64         `json:"max_cpu_percent,omitempty"`
	SustainSeconds  int64           `json:"sustain_seconds"`
	CooldownSeconds int64           `json:"cooldown_seconds"`
	Pending         []PendingAction `json:"pending"`
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
}

type sessionState struct {
	breachSince   time.Time
	pendingID     string
	cooldownUntil time.Time
	contained     bool
}

type Controller struct {
	mu        sync.Mutex
	policy    Policy
	states    map[string]*sessionState
	pending   map[string]PendingAction
	latest    Snapshot
	seq       uint64
	terminate func(ControlAction) error
}

func NewController(policy Policy, terminate func(ControlAction) error) *Controller {
	return &Controller{policy: normalizedPolicy(policy), states: map[string]*sessionState{},
		pending: map[string]PendingAction{}, terminate: terminate}
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
	return p
}

func (c *Controller) SetPolicy(p Policy) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policy = normalizedPolicy(p)
	c.states = map[string]*sessionState{}
	c.pending = map[string]PendingAction{}
	for i := range c.latest.Sessions {
		c.latest.Sessions[i].Control = nil
	}
}

func (c *Controller) SetTerminator(fn func(ControlAction) error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.terminate = fn
}

func (c *Controller) Observe(snapshot Snapshot, now time.Time) {
	c.mu.Lock()
	policy := c.policy
	live := make(map[string]bool, len(snapshot.Sessions))
	var automatic []ControlAction
	for i := range snapshot.Sessions {
		s := &snapshot.Sessions[i]
		live[s.Key] = true
		violations := policyViolations(policy, *s)
		control := &SessionControl{Mode: policy.Mode, State: StateHealthy, Violations: violations}
		s.Control = control
		state := c.states[s.Key]
		if state == nil {
			state = &sessionState{}
			c.states[s.Key] = state
		}
		if len(violations) == 0 {
			delete(c.pending, state.pendingID)
			*state = sessionState{}
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
		targetPID, targetStartedAt := containmentTarget(*s)
		action := ControlAction{Kind: "terminate", SessionKey: s.Key, RootPID: s.RootPID,
			RootStartedAt: s.RootStartedAt, TargetPID: targetPID, TargetStartedAt: targetStartedAt,
			Name: s.Name, Workspace: s.Workspace,
			Violations: append([]Violation(nil), violations...)}
		switch policy.Mode {
		case ModePrompt:
			if state.pendingID == "" {
				c.seq++
				state.pendingID = fmt.Sprintf("resource-%d", c.seq)
				c.pending[state.pendingID] = PendingAction{ID: state.pendingID, SessionKey: s.Key,
					RootPID: s.RootPID, Name: s.Name, Workspace: s.Workspace, CreatedAt: now,
					Violations: append([]Violation(nil), violations...)}
			}
			control.State, control.PendingID = StateApproval, state.pendingID
		case ModeTerminate:
			if !state.contained && c.terminate != nil {
				state.contained = true
				control.State = StateContained
				automatic = append(automatic, action)
			} else if state.contained {
				control.State = StateContained
			} else {
				control.State = StateExceeded
			}
		default:
			control.State = StateExceeded
		}
	}
	for key, state := range c.states {
		if !live[key] {
			delete(c.pending, state.pendingID)
			delete(c.states, key)
		}
	}
	snapshot.Control = c.controlSnapshotLocked(policy)
	c.latest = cloneSnapshot(snapshot)
	terminate := c.terminate
	c.mu.Unlock()
	if terminate != nil {
		for _, action := range automatic {
			if err := terminate(action); err != nil {
				c.mu.Lock()
				if state := c.states[action.SessionKey]; state != nil {
					state.contained = false
					state.cooldownUntil = now.Add(policy.Cooldown)
					c.setLatestControlStateLocked(action.SessionKey, StateCooldown, "")
				}
				c.mu.Unlock()
			}
		}
	}
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
	s.Control = c.controlSnapshotLocked(c.policy)
	for i := range s.Sessions {
		if st := c.states[s.Sessions[i].Key]; st != nil && st.pendingID != "" && s.Sessions[i].Control != nil {
			s.Sessions[i].Control.PendingID = st.pendingID
		}
	}
	return s
}

func (c *Controller) controlSnapshotLocked(p Policy) *ControlSnapshot {
	pending := make([]PendingAction, 0, len(c.pending))
	for _, item := range c.pending {
		pending = append(pending, item)
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].CreatedAt.Before(pending[j].CreatedAt) })
	return &ControlSnapshot{Mode: p.Mode, MaxRSSBytes: p.MaxRSSBytes, MaxCPUPercent: p.MaxCPUPercent,
		SustainSeconds: int64(p.Sustain.Seconds()), CooldownSeconds: int64(p.Cooldown.Seconds()), Pending: pending}
}

func (c *Controller) Resolve(id, decision string, now time.Time) error {
	c.mu.Lock()
	pending, ok := c.pending[id]
	if !ok {
		c.mu.Unlock()
		return fmt.Errorf("resource action not found")
	}
	if decision != "terminate" && decision != "dismiss" {
		c.mu.Unlock()
		return fmt.Errorf("decision must be terminate or dismiss")
	}
	if decision == "dismiss" {
		delete(c.pending, id)
		if state := c.states[pending.SessionKey]; state != nil {
			state.pendingID = ""
			state.cooldownUntil = now.Add(c.policy.Cooldown)
			c.setLatestControlStateLocked(pending.SessionKey, StateCooldown, "")
		}
		c.mu.Unlock()
		return nil
	}
	var action ControlAction
	if decision == "terminate" {
		for _, s := range c.latest.Sessions {
			if s.Key == pending.SessionKey {
				targetPID, targetStartedAt := containmentTarget(s)
				action = ControlAction{Kind: decision, SessionKey: s.Key, RootPID: s.RootPID,
					RootStartedAt: s.RootStartedAt, TargetPID: targetPID, TargetStartedAt: targetStartedAt,
					Name: s.Name, Workspace: s.Workspace,
					Violations: pending.Violations}
				break
			}
		}
	}
	terminate := c.terminate
	c.mu.Unlock()
	if action.TargetPID == 0 {
		return fmt.Errorf("session is no longer active")
	}
	if terminate == nil {
		return fmt.Errorf("resource containment is unavailable")
	}
	if err := terminate(action); err != nil {
		return err // keep the approval pending so the operator can retry
	}
	c.mu.Lock()
	delete(c.pending, id)
	if state := c.states[pending.SessionKey]; state != nil {
		state.pendingID = ""
		state.contained = true
		state.cooldownUntil = now.Add(c.policy.Cooldown)
		c.setLatestControlStateLocked(pending.SessionKey, StateContained, "")
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
	for i := range c.latest.Sessions {
		if c.latest.Sessions[i].Key != sessionKey || c.latest.Sessions[i].Control == nil {
			continue
		}
		c.latest.Sessions[i].Control.State = state
		c.latest.Sessions[i].Control.PendingID = pendingID
		return
	}
}
