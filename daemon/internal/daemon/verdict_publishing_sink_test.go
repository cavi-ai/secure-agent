package daemon

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestVerdictPublishingSinkFailureAndRecovery(t *testing.T) {
	for _, kind := range []string{"flag", "incident"} {
		t.Run(kind, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "e.db")
			st, err := store.Open(dbPath, "")
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			st.PutFlag(model.Flag{ID: "subject", TS: time.Now(), Severity: 3})
			st.PutAdvisorVerdict("subject", kind, model.AdvisorVerdict{Rationale: "saved", CreatedAt: time.Now()})
			db, err := sql.Open("sqlite", dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec(`CREATE TRIGGER fail_verdict BEFORE INSERT ON advisor_verdicts BEGIN SELECT RAISE(ABORT, 'injected verdict failure'); END`); err != nil {
				t.Fatal(err)
			}
			hub := api.NewDeltaHub()
			sub := hub.Subscribe()
			defer hub.Close()
			postureCalls := 0
			sink := &verdictPublishingSink{Store: st, deltaHub: hub, postureChanged: func() { postureCalls++ }}
			verdict := model.AdvisorVerdict{Rationale: "new", CreatedAt: time.Now()}
			if err := sink.PutAdvisorVerdict("subject", kind, verdict); err == nil {
				t.Fatal("failed verdict reported persistence success")
			}
			select {
			case delta := <-sub:
				t.Fatalf("failed verdict published a delta: %+v", delta)
			default:
			}
			if got, ok := st.AdvisorVerdictFor("subject", kind); !ok || got.Rationale != "saved" {
				t.Fatalf("failed verdict overwrote saved data: %+v, %v", got, ok)
			}
			h := st.WriteHealth()
			if h.Failures != 1 || len(h.Active) != 1 || h.Active[0] != "advisor verdicts" || postureCalls != 1 {
				t.Fatalf("verdict failure hidden: health=%+v posture calls=%d", h, postureCalls)
			}
			if _, err := db.Exec("DROP TRIGGER fail_verdict"); err != nil {
				t.Fatal(err)
			}
			if err := sink.PutAdvisorVerdict("subject", kind, verdict); err != nil {
				t.Fatal(err)
			}
			if got, ok := st.AdvisorVerdictFor("subject", kind); !ok || got.Rationale != "new" {
				t.Fatalf("verdict did not recover: %+v, %v", got, ok)
			}
			h = st.WriteHealth()
			if h.Failures != 1 || len(h.Active) != 0 || postureCalls != 2 {
				t.Fatalf("recovery lost failure history or failed to refresh posture: health=%+v calls=%d", h, postureCalls)
			}
			select {
			case delta := <-sub:
				if kind != "flag" || delta.Type != "flag" || delta.Data.(model.Flag).Advisor == nil || delta.Data.(model.Flag).Advisor.Rationale != "new" {
					t.Fatalf("unexpected recovered verdict delta: %+v", delta)
				}
			default:
				if kind == "flag" {
					t.Fatal("recovered flag verdict was not published")
				}
			}
		})
	}
}

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
	if !postureCalled {
		t.Fatal("non-flag verdict must refresh evidence health in posture")
	}
}
