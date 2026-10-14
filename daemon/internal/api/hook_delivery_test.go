package api

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
)

func TestDeliveryAttentionUsesExplicitScopeAndClearsOnlyActiveError(t *testing.T) {
	for _, session := range []string{"", "session-1"} {
		t.Run("scope="+session, func(t *testing.T) {
			a := attentionAPI(t, nil)
			a.store.TrackHookIngestion()
			r := hookrun.ForwarderReport{Type: "hook_forwarder", Version: 2, Harness: "hermes", ForwarderID: "host-1", SessionID: session, Sequence: 1, TS: time.Now().UTC(), State: "error", Pending: 3, Dropped: 1,
				Health: &hookrun.ForwarderHealth{SourceState: "connected", DeliveryError: hookrun.ErrRecorderFailed}}
			a.store.NoteHookForwarder(r)
			a.store.NoteHookForwarder(r)
			g := attentionGroups(a)
			if len(g) != 1 || len(g[0].Items) != 1 || g[0].Items[0].Kind != "hook_delivery" || g[0].Items[0].SessionID != session || g[0].RootPID != 0 {
				t.Fatalf("delivery missing, duplicated or misattributed: %+v", g)
			}
			r.Sequence++
			r.TS = time.Now().UTC()
			r.State = "connected"
			r.Pending = 0
			r.Health.DeliveryError = ""
			r.DeliveryFailures = 3
			a.store.NoteHookForwarder(r)
			if g := attentionGroups(a); len(g) != 0 {
				t.Fatalf("historical counters kept an active alert: %+v", g)
			}
			p := derivePosture(a.loadPostureInputs(Status{Running: true}, nil, nil, nil))
			var gap bool
			for _, item := range p.CoverageItems {
				if item.Kind == "hook_evidence_gap" {
					gap = true
				}
			}
			if !gap {
				t.Fatal("recovery hid dropped evidence")
			}
		})
	}
}
