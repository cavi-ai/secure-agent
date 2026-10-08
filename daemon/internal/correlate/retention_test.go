package correlate

import (
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"testing"
	"time"
)

func TestPartialInspectionIsCoverageWarning(t *testing.T) {
	c := newTestCorrelator(t)
	flags := c.Observe(event.Event{Kind: event.KindProxyHit, TS: time.Now(), RemoteHost: "example.invalid", Detail: "proxy-inspection-incomplete:body-limit"})
	if len(flags) != 1 || flags[0].Severity != 2 || flags[0].Rule != "proxy-inspection-incomplete" {
		t.Fatalf("partial scan misclassified: %+v", flags)
	}
}

func TestRetentionPrunesWithoutMovingBackwardForLateEvents(t *testing.T) {
	c := newTestCorrelator(t)
	base := time.Now()
	c.marks[1] = []readMark{{at: base.Add(-11 * time.Minute)}, {at: base}}
	c.conns[1] = []connMark{{at: base.Add(-11 * time.Minute)}, {at: base}}
	c.evictStaleLocked(base)
	if len(c.marks[1]) != 1 || len(c.conns[1]) != 1 {
		t.Fatal("stale marks retained")
	}
	c.evictStaleLocked(base.Add(-time.Minute))
	if !c.lastEviction.Equal(base) {
		t.Fatal("late event moved housekeeping backward")
	}
	c.evictStaleLocked(base.Add(11 * time.Minute))
	if len(c.marks) != 0 || len(c.conns) != 0 {
		t.Fatal("expired PIDs retained")
	}
}
