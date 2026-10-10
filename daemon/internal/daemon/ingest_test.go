package daemon

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
	"github.com/cavi-ai/secure-agent/daemon/internal/session"
)

func TestIngestStopDrainsProjectionAndRejectsLaterFeed(t *testing.T) {
	f := newPersistenceFixture(t)
	i := newEventIngest(ingestDeps{Store: f.store, Correlator: correlate.New(f.tagger, sensitive.New(f.cfg), f.cfg, correlate.Hooks{}), Resolver: session.NewResolver(f.store, f.tagger), Tagger: f.tagger})
	e := event.Event{Kind: event.KindConnOpen, TS: time.Now(), PID: 500, RemoteHost: "api.example.com", RemotePort: 443}
	if !i.Feed(e) {
		t.Fatal("live feed rejected")
	}
	i.Stop()
	i.Stop()
	select {
	case <-i.Done():
	default:
		t.Fatal("stop did not finish")
	}
	if i.Feed(e) {
		t.Fatal("stopped ingest accepted a new event")
	}
	if len(f.store.RecentEvents(10)) != 1 || len(f.store.ListEgressEpisodesForReview()) != 1 {
		t.Fatal("stop lost persisted activity or queued projection")
	}
}
