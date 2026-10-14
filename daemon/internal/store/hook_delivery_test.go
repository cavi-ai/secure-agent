package store

import (
	"github.com/cavi-ai/secure-agent/daemon/internal/hookhealth"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
)

func TestHookDeliveryAssessmentAcrossHarnesses(t *testing.T) {
	for _, harness := range []string{"claude", "codex", "openclaw", "hermes", "opencode"} {
		t.Run(harness, func(t *testing.T) {
			s, err := Open("", "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			s.TrackHookIngestion()
			now := time.Now().UTC()
			r := hookrun.ForwarderReport{Type: "hook_forwarder", Version: 2, Harness: harness, ForwarderID: "host-1", Sequence: 1, TS: now, State: "error", Pending: 3, Dropped: 1,
				Health: &hookrun.ForwarderHealth{SourceState: "connected", DeliveryError: hookrun.ErrRecorderUnavailable, Outbox: &hookrun.OutboxHealth{Persisted: 2}}}
			s.noteHookForwarder(r, now)
			assessment := func(at time.Time) hookhealth.DeliveryAssessment {
				return s.hookIngestionAt(at).Forwarders[0].Assessment
			}
			a := assessment(now)
			if a.State != "needs-action" || len(a.Issues) != 1 || a.Issues[0].Code != "recorder-unavailable" || a.Issues[0].NextAction == "" || !a.EvidenceGap {
				t.Fatalf("missing delivery assessment: %+v", a)
			}
			if a := assessment(now.Add(3 * time.Minute)); a.State != "unknown" || len(a.Issues) != 0 || !a.EvidenceGap {
				t.Fatalf("staleness invented recovery: %+v", a)
			}
			r.Sequence++
			r.State = "connected"
			r.Health.DeliveryError = ""
			r.DeliveryFailures = 5
			r.Pending = 0
			r.Health.Outbox.Persisted = 0
			s.noteHookForwarder(r, now)
			if a := assessment(now); a.State != "no-active-error" || len(a.Issues) != 0 || !a.EvidenceGap {
				t.Fatalf("historical counters became an active failure or evidence loss vanished: %+v", a)
			}
		})
	}
}
