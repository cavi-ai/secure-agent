package correlate

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestPayloadOutcomeChangesRemainSeparateWithinRepeatWindow(t *testing.T) {
	c := newTestCorrelator(t)
	base := time.Now()
	seen := map[string]bool{}
	for i, tc := range []struct {
		layer, field, action, session string
		port                          int
	}{
		{"pattern", "body", "block", "a", 443},
		{"pattern", "body", "would-block", "a", 443},
		{"fingerprint", "body", "block", "a", 443},
		{"pattern", "query", "block", "a", 443},
		{"pattern", "body", "block", "b", 443},
		{"pattern", "body", "block", "a", 8443},
	} {
		var ev event.Event
		err := json.Unmarshal([]byte(fmt.Sprintf(`{"payload":{"layer":%q,"field":%q,"verdict":"leak","finding_action":%q,"request_action":%q}}`, tc.layer, tc.field, tc.action, tc.action)), &ev)
		if err != nil {
			t.Fatal(err)
		}
		ev.Kind, ev.PID, ev.TS, ev.RemoteHost, ev.RemotePort, ev.SessionID, ev.Detail = event.KindProxyHit, 200, base.Add(time.Duration(i)*time.Second), "outside.invalid", tc.port, tc.session, "proxy-secret-leak:fixture"
		flags := c.Observe(ev)
		if len(flags) != 1 {
			t.Fatalf("changed context suppressed: %+v, flags=%+v", tc, flags)
		}
		if seen[flags[0].ID] {
			t.Fatal("distinct evidence collided")
		}
		seen[flags[0].ID] = true
		a := model.AssessFinding(flags[0])
		want := "blocked"
		if tc.action == "would-block" {
			want = "observed-only"
		}
		if a.Control != want {
			t.Fatalf("producer outcome lost: %+v", a)
		}
		ev.TS = ev.TS.Add(time.Millisecond)
		if repeat := c.Observe(ev); len(repeat) != 0 {
			t.Fatalf("identical context created repeat work: %+v", repeat)
		}
	}
}
