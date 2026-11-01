package daemon

import (
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/testutil"
	"strconv"
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

func TestQueuedFileBatchPreservesValidRowsWhenOneWriteFails(t *testing.T) {
	f := newPersistenceFixture(t)
	f.exec(t, `CREATE TRIGGER reject_file BEFORE INSERT ON events WHEN NEW.path='/work/reject' BEGIN SELECT RAISE(ABORT,'write rejected'); END`)
	at := time.Now()
	deltas, _, _ := f.drain(t,
		event.Event{Kind: event.KindFileOpen, TS: at, PID: 500, Path: "/work/a"},
		event.Event{Kind: event.KindFileOpen, TS: at, PID: 500, Path: "/work/reject"},
		event.Event{Kind: event.KindFileOpen, TS: at, PID: 500, Path: "/work/b"},
	)
	rows := testutil.Read[[]event.Event](t)(f.store.QueryEvents(store.EventFilter{Limit: 10}))
	if len(rows) != 2 {
		t.Fatalf("stored %d rows, want both valid rows", len(rows))
	}
	for _, d := range deltas {
		if e, ok := d.Data.(event.Event); ok && e.Path == "/work/reject" {
			t.Fatal("published failed evidence")
		}
	}
}

func TestQueuedFileBatchFlushesBeforeFindingAndFoldsRepeatedOpens(t *testing.T) {
	f := newPersistenceFixture(t)
	f.exec(t, `CREATE TRIGGER check_finding_order BEFORE INSERT ON flags WHEN NOT EXISTS(SELECT 1 FROM events WHERE path='/work/before') OR EXISTS(SELECT 1 FROM events WHERE path='/work/after') BEGIN SELECT RAISE(ABORT,'evidence ordering violated'); END`)
	at := time.Now()
	deltas, flags, _ := f.drain(t,
		event.Event{Kind: event.KindFileOpen, TS: at, PID: 500, Path: "/work/before"},
		event.Event{Kind: event.KindFileOpen, TS: at, PID: 500, Path: "/work/before"},
		event.Event{Kind: event.KindPluginAction, TS: at, PID: 500, Path: "/Users/x/project/.env"},
		event.Event{Kind: event.KindConnOpen, TS: at.Add(time.Second), PID: 500, RemoteHost: "outside.example.com", RemotePort: 443},
		event.Event{Kind: event.KindFileOpen, TS: at.Add(2 * time.Second), PID: 500, Path: "/work/after"},
	)
	if len(flags) != 1 {
		t.Fatalf("expected a stored finding between file batches, got %d", len(flags))
	}
	rows := testutil.Read[[]event.Event](t)(f.store.QueryEvents(store.EventFilter{Limit: 10}))
	if len(rows) != 4 {
		t.Fatalf("stored %d rows, want 4 with repeated open folded", len(rows))
	}
	if len(deltas) == 0 {
		t.Fatal("stored evidence was not published")
	}
}

// Unattributed opens and repeats of a queued open do not split the batch:
// the agent's file activity commits once, the repeat folds into its stored
// open, and nothing outside the agent family is stored.
func TestQueuedFileBatchSurvivesInterleavedSkippedEvents(t *testing.T) {
	f := newPersistenceFixture(t)
	var batches [][]event.Event
	at := time.Now()
	agent := func(kind event.Kind, path string, n int) event.Event {
		return event.Event{Kind: kind, TS: at.Add(time.Duration(n) * time.Millisecond), PID: 500, ExePath: "/usr/local/bin/cursor-agent", Path: path}
	}
	other := func(path string, n int) event.Event {
		return event.Event{Kind: event.KindFileOpen, TS: at.Add(time.Duration(n) * time.Millisecond), PID: 900, ExePath: "/usr/libexec/mdworker", Path: path}
	}
	input := make(chan event.Event, 16)
	for _, e := range []event.Event{
		agent(event.KindFileOpen, "/work/a", 0), other("/Users/x/Documents/1", 1),
		agent(event.KindFileOpen, "/work/b", 2), other("/Users/x/Documents/2", 3),
		agent(event.KindFileOpen, "/work/a", 4), other("/Users/x/Documents/3", 5),
		agent(event.KindFileWrite, "/work/c", 6), other("/Users/x/Documents/4", 7),
	} {
		input <- e
	}
	close(input)
	cr := correlate.New(f.tagger, sensitive.New(f.cfg), f.cfg, correlate.Hooks{})
	done := runEventIngest(input, ingestDeps{Store: f.store, Correlator: cr, Resolver: session.NewResolver(f.store, f.tagger), Tagger: f.tagger,
		RecordEgressObservation: f.store.RecordEgressObservationForTest,
		PutFileEvents: func(events []event.Event) (store.WriteResult, error) {
			batches = append(batches, append([]event.Event(nil), events...))
			return f.store.PutFileEvents(events)
		}}).Done()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("drain did not finish")
	}
	if len(batches) != 1 || len(batches[0]) != 3 {
		t.Fatalf("file batches = %d (first %d events), want one batch of the agent's three distinct events", len(batches), len(batches[0]))
	}
	rows := testutil.Read[[]event.Event](t)(f.store.QueryEvents(store.EventFilter{Limit: 10}))
	if len(rows) != 3 {
		t.Fatalf("stored %d rows, want 3 with the repeated open folded and unattributed opens skipped", len(rows))
	}
	for _, r := range rows {
		if r.PID != 500 {
			t.Fatalf("stored an unattributed event: %+v", r)
		}
	}
}

// A queue longer than one stored batch commits in batches of at most
// store.MaxFileBatch rows.
func TestQueuedFileBatchCommitsAtMostMaxFileBatchRows(t *testing.T) {
	f := newPersistenceFixture(t)
	const n = store.MaxFileBatch + 36
	input := make(chan event.Event, n)
	at := time.Now()
	for k := 0; k < n; k++ {
		input <- event.Event{Kind: event.KindFileOpen, TS: at.Add(time.Duration(k) * time.Millisecond), PID: 500, ExePath: "/usr/local/bin/cursor-agent", Path: "/work/f" + strconv.Itoa(k)}
	}
	close(input)
	var sizes []int
	cr := correlate.New(f.tagger, sensitive.New(f.cfg), f.cfg, correlate.Hooks{})
	done := runEventIngest(input, ingestDeps{Store: f.store, Correlator: cr, Resolver: session.NewResolver(f.store, f.tagger), Tagger: f.tagger,
		RecordEgressObservation: f.store.RecordEgressObservationForTest,
		PutFileEvents: func(events []event.Event) (store.WriteResult, error) {
			sizes = append(sizes, len(events))
			return f.store.PutFileEvents(events)
		}}).Done()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("drain did not finish")
	}
	if len(sizes) != 2 || sizes[0] != store.MaxFileBatch || sizes[1] != 36 {
		t.Fatalf("batch sizes = %v, want [%d 36]", sizes, store.MaxFileBatch)
	}
	if rows := testutil.Read[[]event.Event](t)(f.store.QueryEvents(store.EventFilter{Limit: 2 * n})); len(rows) != n {
		t.Fatalf("stored %d rows, want %d", len(rows), n)
	}
}

func TestQueuedFileBatchPublishesEveryStoredFile(t *testing.T) {
	f := newPersistenceFixture(t)
	at := time.Now()
	deltas, flags, _ := f.drain(t,
		event.Event{Kind: event.KindFileOpen, TS: at, PID: 500, Path: "/work/a"},
		event.Event{Kind: event.KindFileWrite, TS: at, PID: 500, Path: "/work/b"},
		event.Event{Kind: event.KindFileDelete, TS: at, PID: 500, Path: "/work/c"},
	)
	if len(flags) != 0 {
		t.Fatalf("ordinary file activity raised %d flags", len(flags))
	}
	var paths []string
	for _, d := range deltas {
		if e, ok := d.Data.(event.Event); ok && d.Type == "event" {
			paths = append(paths, e.Path)
		}
	}
	if len(paths) != 3 || paths[0] != "/work/a" || paths[1] != "/work/b" || paths[2] != "/work/c" {
		t.Fatalf("file delivery order=%v", paths)
	}
	rows := testutil.Read[[]event.Event](t)(f.store.QueryEvents(store.EventFilter{Limit: 10}))
	if len(rows) != 3 {
		t.Fatalf("published file evidence differs from storage: %d rows", len(rows))
	}
}
