package hookhealth

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
)

func TestInvalidDeliveryReportCannotCreateEvidenceGap(t *testing.T) {
	r := hookrun.ForwarderReport{Dropped: 1}
	a := AssessDelivery(r, "recent")
	if a.State != "unknown" || a.EvidenceGap || len(a.Issues) > 0 {
		t.Fatalf("unvalidated report became a diagnosis: %+v", a)
	}
}

func TestDeliveryLegacyAndCurrentSignalsDoNotConfuseNoiseWithErrors(t *testing.T) {
	r := hookrun.ForwarderReport{Type: "hook_forwarder", Version: 1, Harness: "codex", ForwarderID: "host", Sequence: 1, TS: time.Now().UTC(), State: "connected", Pending: 3, DeliveryFailures: 5}
	if a := AssessDelivery(r, "recent"); a.State != "no-active-error" || len(a.Issues) > 0 {
		t.Fatalf("backlog and historical attempts became an alert: %+v", a)
	}
	r.State = "error"
	if a := AssessDelivery(r, "recent"); a.State != "needs-action" || len(a.Issues) != 1 || a.Issues[0].Code != "legacy-error" {
		t.Fatalf("legacy failure lost: %+v", a)
	}
	r.Version = 2
	r.Health = &hookrun.ForwarderHealth{SourceState: "error", CaptureError: hookrun.ErrQueueFull, DeliveryError: hookrun.ErrRecorderFailed, Outbox: &hookrun.OutboxHealth{Persisted: 1, Error: hookrun.ErrOutboxFull}}
	if a := AssessDelivery(r, "recent"); a.State != "needs-action" || len(a.Issues) != 4 {
		t.Fatalf("independent errors collapsed: %+v", a)
	}
	for _, freshness := range []string{"stale", "unverified"} {
		if a := AssessDelivery(r, freshness); a.State != "unknown" || len(a.Issues) > 0 {
			t.Fatalf("old evidence became current error: %+v", a)
		}
	}
	r.State = "disconnected"
	r.Health = &hookrun.ForwarderHealth{SourceState: "disconnected", ReportError: true}
	if a := AssessDelivery(r, "recent"); a.State != "no-active-error" || len(a.Issues) > 0 {
		t.Fatalf("disconnect or previous report failure invented an active delivery error: %+v", a)
	}
}
