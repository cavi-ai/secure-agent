package api

import (
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/posture"
)

func TestPosturePublishesCategoryChangesAtUnchangedCounts(t *testing.T) {
	a := newTestAPI(Deps{Telemetry: TelemetryDeps{DeltaHub: NewDeltaHub()}})
	ch := a.deltaHub.Subscribe()
	defer a.deltaHub.Unsubscribe(ch)
	p := Posture{State: "attention", NeedsYou: 1, AttentionSummary: posture.DeriveAttentionSummary([]AttentionGroup{{Items: []AttentionItem{{Kind: "guard", ID: "one"}}}}, nil)}
	a.publishPosture(1, p, false)
	<-ch
	p.AttentionSummary = posture.DeriveAttentionSummary([]AttentionGroup{{Items: []AttentionItem{{Kind: "hook", ID: "two"}}}}, nil)
	a.publishPosture(2, p, false)
	select {
	case <-ch:
	default:
		t.Fatal("same-count category change was suppressed")
	}
	a.publishPosture(3, p, false)
	select {
	case <-ch:
		t.Fatal("unchanged summary published again")
	default:
	}
}
