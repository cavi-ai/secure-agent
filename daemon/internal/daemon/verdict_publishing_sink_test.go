package daemon

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// A verdict that lands asynchronously (after the flag's own delta already
// went out) must still reach a subscribed popover immediately: the popover
// refetches only on flag/posture/guard delta frames, and store.PutAdvisorVerdict
// itself publishes nothing, so without this wrapper the popover would show
// the pre-advisor verdict until its 30s poll.
func TestVerdictPublishingSinkPublishesFlagDeltaWithAdvisor(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "e.db"), filepath.Join(dir, "e.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	st.PutFlag(model.Flag{ID: "f1", Rule: "sensitive-read-then-connect", Severity: 3,
		TS: time.Now().UTC(), PID: 1, Agent: "codex"})

	hub := api.NewDeltaHub()
	sub := hub.Subscribe()
	defer hub.Unsubscribe(sub)

	postureCalled := false
	sink := &verdictPublishingSink{Store: st, deltaHub: hub, postureChanged: func() { postureCalled = true }}

	sink.PutAdvisorVerdict("f1", "flag", model.AdvisorVerdict{
		Assessment: "benign", Confidence: 0.9, Rationale: "routine", CreatedAt: time.Now().UTC(),
	})

	select {
	case d := <-sub:
		if d.Type != "flag" {
			t.Fatalf("delta type = %q, want %q", d.Type, "flag")
		}
		fl, ok := d.Data.(model.Flag)
		if !ok {
			t.Fatalf("delta data is %T, want model.Flag", d.Data)
		}
		if fl.ID != "f1" {
			t.Fatalf("delta flag id = %q, want f1", fl.ID)
		}
		if fl.Advisor == nil || fl.Advisor.Assessment != "benign" {
			t.Fatalf("delta flag advisor = %+v, want assessment benign", fl.Advisor)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no flag delta published for the async verdict")
	}
	if !postureCalled {
		t.Fatal("posture recompute was not triggered")
	}
}

// A non-flag verdict (incident, host, guard, worktree) must not publish a
// flag delta — GetFlagWithAdvisor would just fail the lookup, but the
// intent is explicit: only "flag" verdicts feed the popover's flag delta.
func TestVerdictPublishingSinkIgnoresNonFlagKind(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "e.db"), filepath.Join(dir, "e.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	hub := api.NewDeltaHub()
	sub := hub.Subscribe()
	defer hub.Unsubscribe(sub)

	postureCalled := false
	sink := &verdictPublishingSink{Store: st, deltaHub: hub, postureChanged: func() { postureCalled = true }}
	sink.PutAdvisorVerdict("inc-1", "incident", model.AdvisorVerdict{Rationale: "narrative", CreatedAt: time.Now().UTC()})

	select {
	case d := <-sub:
		t.Fatalf("unexpected delta published for incident verdict: %+v", d)
	case <-time.After(200 * time.Millisecond):
	}
	if postureCalled {
		t.Fatal("posture recompute must not fire for a non-flag verdict")
	}
}
