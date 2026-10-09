package resource

import (
	"encoding/json"
	"fmt"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"testing"
	"time"
)

func outcomeRows(t *testing.T, c *Controller) []map[string]any {
	t.Helper()
	raw, err := json.Marshal(c.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if out["interventions"] != nil {
		if err := json.Unmarshal(out["interventions"], &rows); err != nil {
			t.Fatal(err)
		}
	}
	return rows
}

type receiptFaultStore struct {
	rows                []model.InterventionReceipt
	reserveErr, saveErr error
	onReserve           func()
}

func (s *receiptFaultStore) RecentInterventions(string, int) ([]model.InterventionReceipt, error) {
	return s.rows, nil
}
func (s *receiptFaultStore) ReserveIntervention(r model.InterventionReceipt) (bool, error) {
	if s.onReserve != nil {
		s.onReserve()
	}
	if s.reserveErr != nil {
		return false, s.reserveErr
	}
	s.rows = append(s.rows, r)
	return true, nil
}

func TestChangedEvidenceDuringIntentReservationCannotCreateAnotherApproval(t *testing.T) {
	now := time.Now()
	calls := 0
	c := NewController(Policy{Mode: ModePrompt, MaxRSSBytes: 100}, func(ControlAction) error { calls++; return nil })
	snap := controlSnapshot(10, 200, 0)
	st := &receiptFaultStore{}
	_ = c.SetReceiptStore(st)
	c.Observe(snap, now)
	id := c.Snapshot().Control.Pending[0].ID
	st.onReserve = func() {
		snap.Sessions[0].RootStartedAt = snap.Sessions[0].RootStartedAt.Add(time.Second)
		c.Observe(snap, now.Add(time.Second))
		pending := c.Snapshot().Control.Pending
		if len(pending) != 1 || pending[0].ID != id {
			t.Errorf("second approval appeared during in-flight intent: %+v", pending)
		}
	}
	if err := c.Resolve(id, "apply", now); err == nil || calls != 0 {
		t.Fatalf("changed evidence applied: %v %d", err, calls)
	}
}
func (s *receiptFaultStore) SaveIntervention(model.InterventionReceipt) error { return s.saveErr }

func TestMissingResourceReceiptPreventsBlindReplay(t *testing.T) {
	now := time.Now()
	calls := 0
	c := NewController(Policy{Mode: ModePrompt, MaxRSSBytes: 100}, func(ControlAction) error { calls++; return nil })
	st := &receiptFaultStore{saveErr: fmt.Errorf("disk unavailable")}
	if err := c.SetReceiptStore(st); err != nil {
		t.Fatal(err)
	}
	c.Observe(controlSnapshot(10, 200, 0), now)
	id := c.Snapshot().Control.Pending[0].ID
	if err := c.Resolve(id, "apply", now); err == nil {
		t.Fatal("missing result reported saved")
	}
	if err := c.Resolve(id, "apply", now); err == nil || calls != 1 {
		t.Fatalf("operation replayed: %v %d", err, calls)
	}
	rows := outcomeRows(t, c)
	if rows[0]["status"] != "unknown" {
		t.Fatalf("missing receipt hidden: %+v", rows)
	}
	c.Observe(controlSnapshot(10, 0, 0), now.Add(2*time.Second))
	c.Observe(controlSnapshot(10, 200, 0), now.Add(3*time.Second))
	if len(c.Snapshot().Control.Pending) > 0 {
		_ = c.Resolve(c.Snapshot().Control.Pending[0].ID, "apply", now.Add(3*time.Second))
	}
	if calls != 1 {
		t.Fatalf("budget reset replayed an ambiguous operation: %d", calls)
	}
	// The persisted intent survives restart, but the ambiguous action cannot run
	// again against the same process family under automatic policy.
	restarted := NewController(Policy{Mode: ModeTerminate, MaxRSSBytes: 100}, func(ControlAction) error { calls++; return nil })
	if err := restarted.SetReceiptStore(st); err != nil {
		t.Fatal(err)
	}
	restarted.Observe(controlSnapshot(10, 200, 0), now.Add(time.Second))
	if calls != 1 {
		t.Fatalf("restart replayed an ambiguous operation: %d", calls)
	}
}

func TestUnsavedResourceIntentCannotSignal(t *testing.T) {
	calls := 0
	c := NewController(Policy{Mode: ModeTerminate, MaxRSSBytes: 100}, func(ControlAction) error { calls++; return nil })
	_ = c.SetReceiptStore(&receiptFaultStore{reserveErr: fmt.Errorf("disk unavailable")})
	c.Observe(controlSnapshot(10, 200, 0), time.Now())
	if calls != 0 {
		t.Fatal("process action ran without saved intent")
	}
}

func TestMissingSamplesLeaveResourceVerificationUnknown(t *testing.T) {
	now := time.Now()
	c := NewController(Policy{Mode: ModeTerminate, MaxRSSBytes: 100, Interventions: []InterventionStep{{Action: ActionPause}}}, func(ControlAction) error { return nil })
	c.Observe(controlSnapshot(10, 200, 0), now)
	c.Observe(Snapshot{ObservedAt: now.Add(16 * time.Second)}, now.Add(16*time.Second))
	rows := outcomeRows(t, c)
	if rows[0]["status"] != "applied" || rows[0]["verification"] != "unknown" {
		t.Fatalf("missing samples became recovery: %+v", rows)
	}
}

func TestUnknownPauseReceiptStillOffersResume(t *testing.T) {
	c := NewController(Policy{Mode: ModePrompt, MaxRSSBytes: 100, Interventions: []InterventionStep{{Action: ActionPause}}}, func(ControlAction) error { return nil })
	_ = c.SetReceiptStore(&receiptFaultStore{saveErr: fmt.Errorf("disk unavailable")})
	now := time.Now()
	c.Observe(controlSnapshot(10, 200, 0), now)
	_ = c.Resolve(c.Snapshot().Control.Pending[0].ID, "apply", now)
	if !c.Snapshot().Sessions[0].Control.Paused {
		t.Fatal("possibly stopped family lost resume recourse")
	}
}

func TestPartialResumeKeepsExplicitRecoveryAvailable(t *testing.T) {
	now := time.Now()
	resumeCalls := 0
	c := NewController(Policy{Mode: ModePrompt, MaxRSSBytes: 100, Interventions: []InterventionStep{{Action: ActionPause}}}, func(action ControlAction) error {
		if action.Kind == string(ActionResume) {
			resumeCalls++
			if resumeCalls == 1 {
				return &PartialActionError{Cause: fmt.Errorf("one member could not resume")}
			}
		}
		return nil
	})
	c.Observe(controlSnapshot(10, 200, 0), now)
	if err := c.Resolve(c.Snapshot().Control.Pending[0].ID, "apply", now); err != nil {
		t.Fatal(err)
	}
	key := c.Snapshot().Sessions[0].Key
	if err := c.Resume(key, now); err == nil {
		t.Fatal("partial resume reported applied")
	}
	if err := c.Resume(key, now.Add(time.Second)); err != nil || resumeCalls != 2 {
		t.Fatalf("explicit resume recovery blocked: %v calls=%d", err, resumeCalls)
	}
}

func TestRestartedAmbiguousResumeKeepsRecoveryAvailable(t *testing.T) {
	for _, status := range []string{"partial", "unknown", "requested"} {
		t.Run(status, func(t *testing.T) {
			now := time.Now()
			snap := controlSnapshot(10, 200, 0)
			family := snap.Sessions[0]
			calls := 0
			c := NewController(Policy{Mode: ModePrompt, MaxRSSBytes: 100}, func(action ControlAction) error {
				if action.Kind != string(ActionResume) {
					t.Fatalf("replayed non-recovery action: %s", action.Kind)
				}
				calls++
				return nil
			})
			st := &receiptFaultStore{rows: []model.InterventionReceipt{{ID: "earlier-resume", Kind: string(ActionResume), Status: status, SessionKey: family.Key, RootPID: family.RootPID, RootStartedAt: family.RootStartedAt}}}
			if err := c.SetReceiptStore(st); err != nil {
				t.Fatal(err)
			}
			c.Observe(snap, now)
			if calls != 0 || !c.Snapshot().Sessions[0].Control.Paused {
				t.Fatal("ambiguous resume lost explicit recovery or was replayed")
			}
			if err := c.Resume(family.Key, now); err != nil || calls != 1 {
				t.Fatalf("explicit recovery unavailable after restart: %v calls=%d", err, calls)
			}
		})
	}
}

func TestPendingResourceApprovalCannotMoveToChangedProcessIdentity(t *testing.T) {
	now := time.Now()
	calls := 0
	c := NewController(Policy{Mode: ModePrompt, MaxRSSBytes: 100}, func(ControlAction) error { calls++; return nil })
	snap := controlSnapshot(10, 200, 0)
	c.Observe(snap, now)
	id := c.Snapshot().Control.Pending[0].ID
	snap.Sessions[0].RootStartedAt = snap.Sessions[0].RootStartedAt.Add(time.Second)
	c.Observe(snap, now.Add(time.Second))
	if err := c.Resolve(id, "apply", now.Add(2*time.Second)); err == nil || calls != 0 {
		t.Fatalf("stale approval applied: err=%v calls=%d", err, calls)
	}
}

func TestResourceActionApplicationAndObservationAreSeparate(t *testing.T) {
	now := time.Now()
	c := NewController(Policy{Mode: ModeTerminate, MaxRSSBytes: 100, Interventions: []InterventionStep{{Action: ActionPause}}}, func(ControlAction) error { return nil })
	snap := controlSnapshot(10, 200, 120)
	snap.Sessions[0].Processes[0].StartedAt = snap.Sessions[0].RootStartedAt
	c.Observe(snap, now)
	rows := outcomeRows(t, c)
	if len(rows) != 1 || rows[0]["status"] != "applied" || rows[0]["verification"] != "pending" {
		t.Fatalf("missing bounded application result: %+v", rows)
	}
	for i := 1; i <= 3; i++ {
		snap.ObservedAt = now.Add(time.Duration(i) * 5 * time.Second)
		snap.Sessions[0].RSSBytes = 150
		snap.Sessions[0].Samples = []Sample{{At: snap.ObservedAt, RSSBytes: 150, CPUPercent: 20}}
		c.Observe(snap, snap.ObservedAt)
	}
	rows = outcomeRows(t, c)
	if rows[0]["status"] != "applied" || rows[0]["verification"] != "observed" || len(rows[0]["after"].([]any)) != 3 {
		t.Fatalf("observation became recovery or missing: %+v", rows)
	}
}

func TestResourceTerminationNeedsCapturedFamilyAbsence(t *testing.T) {
	now := time.Now()
	c := NewController(Policy{Mode: ModeTerminate, MaxRSSBytes: 100}, func(ControlAction) error { return nil })
	snap := controlSnapshot(10, 200, 0)
	snap.Sessions[0].Processes[0].StartedAt = snap.Sessions[0].RootStartedAt
	c.Observe(snap, now)
	c.Observe(Snapshot{ObservedAt: now.Add(5 * time.Second), Sessions: []Session{}}, now.Add(5*time.Second))
	rows := outcomeRows(t, c)
	if len(rows) != 1 || rows[0]["verification"] != "verified" || rows[0]["verified_by"] != "captured-family-absent" {
		t.Fatalf("absence not retained: %+v", rows)
	}
}
