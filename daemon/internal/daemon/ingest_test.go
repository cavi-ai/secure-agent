package daemon

import (
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/testutil"
	"sync"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
	"github.com/cavi-ai/secure-agent/daemon/internal/session"
)

func TestIngestStopDrainsProjectionAndRejectsLaterFeed(t *testing.T) {
	f := newPersistenceFixture(t)
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	i := newEventIngest(ingestDeps{Store: f.store, Correlator: correlate.New(f.tagger, sensitive.New(f.cfg), f.cfg, correlate.Hooks{}), Resolver: session.NewResolver(f.store, f.tagger), Tagger: f.tagger, RecordEgressObservation: func(o store.EgressObservation) error {
		close(started)
		<-release
		return f.store.RecordEgressObservationForTest(o)
	}})
	t.Cleanup(func() { unblock(); i.Stop() })
	e := event.Event{Kind: event.KindConnOpen, TS: time.Now(), PID: 500, RemoteHost: "api.example.com", RemotePort: 443}
	if !i.Feed(e) {
		t.Fatal("live feed rejected")
	}
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("projection writer did not start")
	}
	stopped := make(chan struct{})
	go func() { i.Stop(); close(stopped) }()
	select {
	case <-i.Done():
		t.Fatal("stop finished before the queued projection")
	case <-time.After(100 * time.Millisecond):
	}
	unblock()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("stop did not drain the released projection")
	}
	i.Stop()
	select {
	case <-i.Done():
	default:
		t.Fatal("stop did not finish")
	}
	if i.Feed(e) {
		t.Fatal("stopped ingest accepted a new event")
	}
	if len(testutil.Read[[]event.Event](t)(f.store.QueryEvents(store.EventFilter{Limit: 10}))) != 1 || len(testutil.Read[[]store.EgressEpisode](t)(f.store.ListEgressEpisodesForReview())) != 1 {
		t.Fatal("stop lost persisted activity or queued projection")
	}
}
