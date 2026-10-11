package correlate

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestSuppressionExpiresDuringUnrelatedObservations(t *testing.T) {
	c := newTestCorrelator(t)
	base := time.Unix(1700000000, 0)
	hit := event.Event{Kind: event.KindProxyHit, RemoteHost: "example.invalid", Detail: "proxy-secret-leak", TS: base}
	first := c.Observe(hit)
	if len(first) != 1 {
		t.Fatalf("initial flags: %+v", first)
	}
	c.ResolvePersistence(first[0].ID, true)
	key := "proxy-secret-leak|0|example.invalid"

	// Keep the existing strict four-hour retention boundary.
	c.Observe(event.Event{Kind: event.KindExec, TS: base.Add(4 * time.Hour)})
	if _, ok := c.lastFire[key]; !ok {
		t.Fatal("suppression removed at the retention boundary")
	}
	c.Observe(event.Event{Kind: event.KindExec, TS: base.Add(4*time.Hour + time.Minute)})
	if len(c.lastFire) != 0 {
		t.Fatalf("expired suppression retained without a new flag: %+v", c.lastFire)
	}

	hit.TS = base.Add(4*time.Hour + time.Minute)
	flags := c.Observe(hit)
	if len(flags) != 1 {
		t.Fatalf("new observation after expiry: %+v", flags)
	}
	c.ResolvePersistence(flags[0].ID, false)
	if len(c.lastFire) != 0 {
		t.Fatal("rejected persistence retained suppression")
	}
	hit.TS = hit.TS.Add(time.Second)
	flags = c.Observe(hit)
	if len(flags) != 1 {
		t.Fatalf("persistence retry: %+v", flags)
	}
	c.ResolvePersistence(flags[0].ID, true)

	// Backdated housekeeping must retain the newer suppression watermark.
	c.Observe(event.Event{Kind: event.KindExec, TS: base})
	hit.TS = hit.TS.Add(time.Second)
	if flags := c.Observe(hit); len(flags) != 0 {
		t.Fatalf("late event cleared active repeat suppression: %+v", flags)
	}
	c.Observe(event.Event{Kind: event.KindExec, TS: hit.TS.Add(time.Minute)})
	if len(c.lastFire) != 1 {
		t.Fatal("scheduled cleanup removed active suppression")
	}
}
