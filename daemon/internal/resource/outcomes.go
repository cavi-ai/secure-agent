package resource

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

type ReceiptStore interface {
	ReserveIntervention(model.InterventionReceipt) (bool, error)
	SaveIntervention(model.InterventionReceipt) error
	RecentInterventions(string, int) ([]model.InterventionReceipt, error)
}

// ConsumedActionError forbids replay of an operation whose effects are partial
// or whose durable result is missing. Its Cause preserves pause recovery.
type ConsumedActionError struct {
	Cause       error
	MaybePaused bool
}

func (e *ConsumedActionError) Error() string { return e.Cause.Error() }
func (e *ConsumedActionError) Unwrap() error { return e.Cause }

// PartialActionError means some members were changed before another failed.
type PartialActionError struct{ Cause error }

func (e *PartialActionError) Error() string { return e.Cause.Error() }
func (e *PartialActionError) Unwrap() error { return e.Cause }

func newActionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("resource action identity unavailable")
	}
	return "resource-" + hex.EncodeToString(b[:])
}

func actionContext(s Session, kind string, nice int, violations []Violation) string {
	targets := identities(s)
	// A changing sample value is not new authority; target identities and the
	// breached budget dimensions/limits are. Policy reload discards approvals.
	limits := append([]Violation(nil), violations...)
	for i := range limits {
		limits[i].Actual = 0
	}
	raw, _ := json.Marshal(struct {
		Key, Workspace, Kind string
		Root                 int32
		Started              time.Time
		Nice                 int
		Targets              []model.ProcessIdentity
		Limits               []Violation
	}{s.Key, s.Workspace, kind, s.RootPID, s.RootStartedAt, nice, targets, limits})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func identities(s Session) []model.ProcessIdentity {
	out := make([]model.ProcessIdentity, 0, len(s.Processes))
	for _, p := range s.Processes {
		out = append(out, model.ProcessIdentity{PID: p.PID, StartedAt: p.StartedAt})
	}
	if len(out) == 0 && s.RootPID > 0 {
		out = append(out, model.ProcessIdentity{PID: s.RootPID, StartedAt: s.RootStartedAt})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

func (c *Controller) SetReceiptStore(st ReceiptStore) error {
	rows, err := st.RecentInterventions("", 200)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.receiptStore = st
	c.receiptHistoryError = err
	if err != nil {
		return err
	}
	// Most recent first on disk, chronological in the controller.
	for i := len(rows) - 1; i >= 0; i-- {
		r := rows[i]
		if r.Status == "requested" || r.Verification == "pending" {
			r.Verification = "unknown"
			r.VerifiedBy = ""
			r.Limits = append(r.Limits, "Observation interrupted by daemon restart; no action was replayed.")
			if r.Status == "requested" {
				r.Status = "unknown"
			}
		}
		c.receipts = append(c.receipts, r)
		c.restoreReceipts = append(c.restoreReceipts, r)
	}
	return nil
}

func (c *Controller) restoreActionStateLocked(s Session, state *sessionState) {
	retained := c.restoreReceipts[:0]
	for _, r := range c.restoreReceipts {
		if r.SessionKey != s.Key {
			retained = append(retained, r)
			continue
		}
		if r.RootPID != s.RootPID || r.RootStartedAt.IsZero() || !r.RootStartedAt.Equal(s.RootStartedAt) {
			continue
		}
		if r.Status != "applied" && r.Status != "partial" && r.Status != "unknown" {
			continue
		}
		action := InterventionAction(r.Kind)
		state.applied[action] = true
		state.lastAction = action
		state.lastError = r.Error
		if r.Status == "unknown" {
			state.lastError = "Earlier process action has an unknown result; it was not replayed."
		}
		if action == ActionPause {
			state.paused = true
		}
		if action == ActionResume {
			// An incomplete resume can leave family members stopped. Keep the
			// explicit, identity-checked recovery control available after restart.
			state.paused = r.Status != "applied"
		}
		if action == ActionTerminate && r.Status == "applied" {
			state.contained = true
		}
	}
	c.restoreReceipts = retained
}

func (c *Controller) executeRecorded(action ControlAction, now time.Time) error {
	c.mu.Lock()
	var family Session
	found := false
	for _, s := range c.latest.Sessions {
		if s.Key == action.SessionKey {
			family = s
			found = true
			break
		}
	}
	execute, st := c.execute, c.receiptStore
	historyError := c.receiptHistoryError
	action.Targets = identities(family)
	for _, previous := range c.receipts {
		// SIGCONT is idempotent recovery requested explicitly by the operator.
		// It still needs a fresh intent and the same process identity checks.
		if action.Kind != string(ActionResume) && previous.SessionKey == action.SessionKey && previous.Kind == action.Kind && previous.RootPID == action.RootPID && previous.RootStartedAt.Equal(action.RootStartedAt) && (previous.Status == "unknown" || previous.Status == "partial") {
			c.mu.Unlock()
			return &ConsumedActionError{Cause: fmt.Errorf("earlier action has a partial or unknown result; reconcile the captured process family before repeating it"), MaybePaused: action.Kind == string(ActionPause)}
		}
	}
	contextKey := actionContext(family, action.Kind, action.Nice, action.Violations)
	r := model.InterventionReceipt{ID: action.IntentID, SourceID: action.IntentID, Revision: 1, SessionKey: action.SessionKey, Kind: action.Kind, RootPID: action.RootPID, RootStartedAt: action.RootStartedAt, RequestedAt: now, Status: "requested", Verification: "unknown", Before: interventionSample(c.latest, family, now, true), After: []model.InterventionSample{}, Targets: identities(family), Limits: actionLimits(action.Kind)}
	if action.Kind == string(ActionResume) {
		r.SourceID = action.SessionKey
	}
	c.mu.Unlock()
	if historyError != nil {
		return fmt.Errorf("action history unavailable; no process action was attempted")
	}
	if !found {
		return fmt.Errorf("session is no longer active")
	}
	if st != nil {
		reserved, err := st.ReserveIntervention(r)
		if err != nil {
			return fmt.Errorf("action intent could not be saved; no process action was attempted")
		}
		if !reserved {
			return &ConsumedActionError{Cause: fmt.Errorf("action already recorded; review its result instead of replaying")}
		}
	}
	c.mu.Lock()
	valid := false
	for _, s := range c.latest.Sessions {
		policy, _ := c.policies.forWorkspace(s.Workspace)
		violations := policyViolations(policy, s)
		if action.Kind == string(ActionResume) {
			violations = nil
		}
		if c.policyRevision == action.PolicyRevision && s.Key == action.SessionKey && contextKey == actionContext(s, action.Kind, action.Nice, violations) {
			valid = true
			break
		}
	}
	c.mu.Unlock()
	var err error
	applicationStarted := time.Now()
	if !valid {
		err = fmt.Errorf("resource evidence changed before application")
		r.Status = "cancelled"
	} else if execute == nil && action.Kind != string(ActionNotify) {
		err = fmt.Errorf("resource intervention is unavailable")
		r.Status = "failed"
	} else {
		if execute != nil {
			err = execute(action)
		}
		r.Status = "applied"
		r.AppliedAt = now.Add(time.Since(applicationStarted))
		r.Verification = "pending"
		if action.Kind == string(ActionNotify) {
			r.Verification = "unknown"
		}
		if err != nil {
			r.Status = "failed"
			r.Verification = "unknown"
			var pause *PartialPauseError
			var partial *PartialActionError
			if errors.As(err, &pause) || errors.As(err, &partial) {
				r.Status = "partial"
				err = &ConsumedActionError{Cause: err}
			}
		}
	}
	if err != nil {
		r.Error = err.Error()
	}
	r.Revision++
	if st != nil {
		if saveErr := st.SaveIntervention(r); saveErr != nil {
			r.Status = "unknown"
			r.Verification = "unknown"
			r.Error = "Process action may have applied; its result could not be saved. Review process state before taking another action."
			err = &ConsumedActionError{Cause: fmt.Errorf("%s", r.Error), MaybePaused: action.Kind == string(ActionPause)}
		}
	}
	c.mu.Lock()
	c.receipts = append(c.receipts, r)
	if len(c.receipts) > 200 {
		c.receipts = c.receipts[len(c.receipts)-200:]
	}
	c.mu.Unlock()
	return err
}

func actionLimits(kind string) []string {
	limits := []string{"Post-action observations do not establish causation or task completion."}
	switch InterventionAction(kind) {
	case ActionPause:
		limits = append(limits, "Pause can stop growth without freeing memory; resume may be needed.")
	case ActionLowerPriority:
		limits = append(limits, "Lower priority addresses CPU contention; it does not reclaim memory.")
	case ActionTerminate:
		limits = append(limits, "Termination can lose unsaved work; verification covers only the captured process family.")
	case ActionResume:
		limits = append(limits, "Resuming can restart resource growth.")
	}
	return limits
}

func interventionSample(snapshot Snapshot, s Session, at time.Time, present bool) model.InterventionSample {
	out := model.InterventionSample{At: at, CapturedFamilyPresent: present}
	if present && s.Key != "" {
		rss, cpu := s.RSSBytes, s.CPUPercent
		out.RSSBytes = &rss
		out.CPUPercent = &cpu
	}
	if h := snapshot.Host; h != nil {
		out.HostCapacity = h.Capacity
		out.HostCPUPercent = cloneFloat(h.SystemCPUPercent)
		if h.TotalMemoryBytes > 0 && h.MemoryPressure != "unknown" {
			available := h.AvailableMemoryBytes
			out.HostAvailableBytes = &available
		}
	}
	return out
}

func (c *Controller) observeOutcomesLocked(snapshot Snapshot, now time.Time) {
	for i := range c.receipts {
		r := &c.receipts[i]
		if r.Verification != "pending" {
			continue
		}
		last := r.AppliedAt
		if len(r.After) > 0 {
			last = r.After[len(r.After)-1].At
		}
		if now.Sub(r.AppliedAt) > 15*time.Second {
			r.Verification = "unknown"
			r.Limits = append(r.Limits, "Fewer than three resource samples were available within 15 seconds.")
		} else {
			if snapshot.ObservedAt.IsZero() || !snapshot.ObservedAt.After(last) {
				continue
			}
			var family Session
			present := false
			for _, s := range snapshot.Sessions {
				for _, p := range identities(s) {
					for _, target := range r.Targets {
						if target.PID == p.PID && !target.StartedAt.IsZero() && target.StartedAt.Equal(p.StartedAt) {
							present = true
						}
					}
				}
				if s.Key == r.SessionKey {
					family = s
				}
			}
			sampleAt := snapshot.ObservedAt
			if family.Key != "" {
				if len(family.Samples) == 0 {
					continue
				}
				latest := family.Samples[len(family.Samples)-1]
				sampleAt = latest.At
				family.RSSBytes, family.CPUPercent = latest.RSSBytes, latest.CPUPercent
			}
			if !sampleAt.After(last) || sampleAt.After(r.AppliedAt.Add(15*time.Second)) {
				continue
			}
			r.After = append(r.After, interventionSample(snapshot, family, sampleAt, present))
			if r.Kind == string(ActionTerminate) && !present && knownTargets(r.Targets) {
				r.Verification = "verified"
				r.VerifiedBy = "captured-family-absent"
			} else if !present || family.Key == "" || !knownTargets(r.Targets) {
				r.Verification = "unknown"
				r.Limits = append(r.Limits, "Captured process family is unavailable or its identity is incomplete.")
			} else if len(r.After) >= 3 {
				r.Verification = "observed"
				r.VerifiedBy = "three-resource-samples"
			}
		}
		r.Revision++
		if c.receiptStore != nil {
			if err := c.receiptStore.SaveIntervention(*r); err != nil {
				r.Verification = "unknown"
				r.VerifiedBy = ""
				r.Limits = append(r.Limits, "Post-action observation could not be saved.")
			}
		}
	}
}

func knownTargets(targets []model.ProcessIdentity) bool {
	if len(targets) == 0 {
		return false
	}
	for _, t := range targets {
		if t.StartedAt.IsZero() {
			return false
		}
	}
	return true
}
func cloneReceipt(r model.InterventionReceipt) model.InterventionReceipt {
	// The receipt is bounded (three numeric samples); a JSON copy also isolates
	// optional numeric pointers from concurrently rendered snapshots.
	raw, _ := json.Marshal(r)
	var out model.InterventionReceipt
	_ = json.Unmarshal(raw, &out)
	return out
}
func cloneReceipts(rows []model.InterventionReceipt) []model.InterventionReceipt {
	out := make([]model.InterventionReceipt, len(rows))
	for i, r := range rows {
		out[i] = cloneReceipt(r)
	}
	return out
}
