package daemon

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/fleet"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
	"github.com/cavi-ai/secure-agent/daemon/internal/session"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type persistenceFixture struct {
	store  *store.Store
	db     *sql.DB
	tagger *agents.Tagger
	cfg    config.Config
}

func newPersistenceFixture(t *testing.T) persistenceFixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.db")
	st, err := store.Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	// Recovery changes triggers while the drain's asynchronous egress
	// projection can still be writing. Match the production store's bounded
	// busy timeout on every fixture connection rather than failing immediately.
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(3000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	cfg, err := config.Load("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	tagger := agents.New(cfg, fakeProcSource{})
	tagger.Refresh()
	return persistenceFixture{st, db, tagger, cfg}
}

func (f persistenceFixture) exec(t *testing.T, query string) {
	t.Helper()
	if _, err := f.db.Exec(query); err != nil {
		t.Fatal(err)
	}
}

func (f persistenceFixture) drain(t *testing.T, events ...event.Event) ([]api.Delta, []model.Flag, []store.WriteHealth) {
	t.Helper()
	hub := api.NewDeltaHub()
	sub := hub.Subscribe()
	defer hub.Close()
	input := make(chan event.Event, len(events))
	for _, e := range events {
		input <- e
	}
	close(input)
	var offered []model.Flag
	var health []store.WriteHealth
	var healthMu sync.Mutex
	cr := correlate.New(f.tagger, sensitive.New(f.cfg), f.cfg, correlate.Hooks{})
	done := runEventIngest(input, ingestDeps{Store: f.store, Correlator: cr, Resolver: session.NewResolver(f.store, f.tagger), Tagger: f.tagger, Deltas: hub, PostureChanged: func() {
		healthMu.Lock()
		defer healthMu.Unlock()
		health = append(health, f.store.WriteHealth())
	}, NewFlag: func(fl model.Flag) { offered = append(offered, fl) }}).Done()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("drain did not finish")
	}
	var deltas []api.Delta
	for {
		select {
		case d := <-sub:
			deltas = append(deltas, d)
		default:
			return deltas, offered, health
		}
	}
}

func TestDrainRejectedEventKeepsGuardLiveAndReportsRecovery(t *testing.T) {
	f := newPersistenceFixture(t)
	f.exec(t, `CREATE TRIGGER reject_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'injected event failure'); END`)
	now := time.Now().UTC()
	deltas, _, health := f.drain(t,
		event.Event{Kind: event.KindToolCall, TS: now, PID: 500, ToolName: "Read", CallID: "failed"},
		event.Event{Kind: event.KindGuardPrompt, TS: now, Detail: "fixture"})
	if len(deltas) != 1 || deltas[0].Type != "guard-prompt" {
		t.Fatalf("failed writes published persisted data or hid live guard notification: %+v", deltas)
	}
	if len(f.store.RecentEvents(10)) != 0 || len(health) == 0 || health[len(health)-1].Failures != 2 {
		t.Fatalf("event failure was not visible: health=%+v", health)
	}
	f.exec(t, "DROP TRIGGER reject_event")
	deltas, _, health = f.drain(t, event.Event{Kind: event.KindToolCall, TS: now.Add(time.Second), PID: 500, ToolName: "Read", CallID: "saved"})
	if len(deltas) != 1 || deltas[0].Type != "event" || len(f.store.RecentEvents(10)) != 1 {
		t.Fatalf("recovered row did not match live feed: %+v", deltas)
	}
	if len(health) == 0 || health[len(health)-1].Failures != 2 || len(health[len(health)-1].Active) != 0 {
		t.Fatalf("recovery was not visible or erased failure history: %+v", health)
	}
}

func TestDrainRejectedFlagDoesNotCreateDependents(t *testing.T) {
	for _, rejection := range []string{"ABORT, 'injected flag failure'", "IGNORE"} {
		t.Run(rejection, func(t *testing.T) {
			f := newPersistenceFixture(t)
			f.exec(t, `CREATE TRIGGER reject_flag BEFORE INSERT ON flags BEGIN SELECT RAISE(`+rejection+`); END`)
			now := time.Now().UTC()
			observations := []event.Event{
				{Kind: event.KindPluginAction, TS: now, PID: 500, Path: "/Users/x/project/.env"},
				{Kind: event.KindConnOpen, TS: now.Add(time.Second), PID: 500, RemoteHost: "evil.example.com", RemotePort: 443},
			}
			deltas, offered, health := f.drain(t, observations...)
			if len(offered) != 0 || len(f.store.RecentFlags(10)) != 0 || len(f.store.RecentIncidents(10)) != 0 {
				t.Fatalf("failed flag started dependent work: offered=%+v", offered)
			}
			for _, d := range deltas {
				if d.Type == "flag" || d.Type == "incident" {
					t.Fatalf("unsaved flag published a durable delta: %+v", d)
				}
			}
			if len(health) == 0 || len(health[len(health)-1].Active) != 1 || health[len(health)-1].Active[0] != "flags" {
				t.Fatalf("failed flag health hidden: %+v", health)
			}
			f.exec(t, "DROP TRIGGER reject_flag")
			_, offered, health = f.drain(t, observations...)
			if len(offered) != 1 || len(f.store.RecentFlags(10)) != 1 || len(f.store.RecentIncidents(10)) != 1 {
				t.Fatalf("recovery did not create saved flag and dependents: %+v", offered)
			}
			if len(health) == 0 || len(health[len(health)-1].Active) != 0 || health[len(health)-1].Failures != 1 {
				t.Fatalf("flag recovery lost health history: %+v", health)
			}
		})
	}
}

func TestDrainDuplicateModelObservationDoesNotPublishNewRow(t *testing.T) {
	f := newPersistenceFixture(t)
	e := event.Event{Kind: event.KindModelCall, TS: time.Now().UTC(), PID: 500, CallID: "call", TokensIn: 100}
	deltas, _, _ := f.drain(t, e, e)
	if len(deltas) != 1 || len(f.store.RecentEvents(10)) != 1 {
		t.Fatalf("duplicate observation published a new row: deltas=%+v", deltas)
	}
}

func TestDrainFlagRecoveryUsesSameCorrelator(t *testing.T) {
	f := newPersistenceFixture(t)
	f.exec(t, `CREATE TRIGGER reject_flag BEFORE INSERT ON flags BEGIN SELECT RAISE(ABORT, 'injected failure'); END`)
	cr := correlate.New(f.tagger, sensitive.New(f.cfg), f.cfg, correlate.Hooks{})
	cr.SetOpenFlagChecker(func(id string) bool {
		flag, ok := f.store.GetFlag(id)
		return ok && !flag.Acknowledged
	})
	input := make(chan event.Event, 4)
	health := make(chan store.WriteHealth, 4)
	var offered []model.Flag
	done := runEventIngest(input, ingestDeps{Store: f.store, Correlator: cr, Resolver: session.NewResolver(f.store, f.tagger), Tagger: f.tagger, PostureChanged: func() { health <- f.store.WriteHealth() }, NewFlag: func(flag model.Flag) { offered = append(offered, flag) }}).Done()
	now := time.Now().UTC()
	input <- event.Event{Kind: event.KindPluginAction, TS: now, PID: 500, Path: "/Users/x/project/.env"}
	conn := event.Event{Kind: event.KindConnOpen, TS: now.Add(time.Second), PID: 500, RemoteHost: "evil.example.com", RemotePort: 443}
	input <- conn
	select {
	case h := <-health:
		if h.Failures != 1 || len(h.Active) != 1 || h.Active[0] != "flags" {
			t.Errorf("initial failure was hidden: %+v", h)
		}
	case <-time.After(3 * time.Second):
		t.Error("failed flag did not refresh health")
	}
	f.exec(t, "DROP TRIGGER reject_flag")
	conn.TS = conn.TS.Add(time.Second)
	input <- conn
	close(input)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("drain did not finish")
	}
	if len(offered) != 1 || len(f.store.RecentFlags(10)) != 1 || len(f.store.RecentIncidents(10)) != 1 {
		t.Fatalf("correlator's failed-flag state prevented recovery: offered=%+v", offered)
	}
}

func TestDrainExportsOnlySavedRowsAndRoutesOnlySavedFlags(t *testing.T) {
	for _, table := range []string{"events", "flags"} {
		t.Run(table, func(t *testing.T) {
			f := newPersistenceFixture(t)
			f.exec(t, `CREATE TRIGGER reject_write BEFORE INSERT ON `+table+` BEGIN SELECT RAISE(ABORT, 'injected failure'); END`)
			delivered := make(chan string, 8)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var envelope fleet.Envelope
				if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
					t.Errorf("decode webhook: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				delivered <- envelope.Kind
			}))
			defer server.Close()
			pub := fleet.NewPublisher()
			pub.AddSink(fleet.NewSink(fleet.WebhookConfig{URL: server.URL, Secret: "test"}, "fixture", "test", ""))
			now := time.Now().UTC()
			input := make(chan event.Event, 3)
			input <- event.Event{Kind: event.KindModelCall, TS: now, PID: 500, CallID: "model", TokensIn: 100}
			input <- event.Event{Kind: event.KindPluginAction, TS: now, PID: 500, Path: "/Users/x/project/.env"}
			input <- event.Event{Kind: event.KindConnOpen, TS: now.Add(time.Second), PID: 500, RemoteHost: "evil.example.com", RemotePort: 443}
			close(input)
			routed := 0
			done := runEventIngest(input, ingestDeps{Store: f.store, Correlator: correlate.New(f.tagger, sensitive.New(f.cfg), f.cfg, correlate.Hooks{}), Fleet: pub, Resolver: session.NewResolver(f.store, f.tagger), Tagger: f.tagger, Advisor: func() *advisor.Subscriber { routed++; return nil }}).Done()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("drain did not finish")
			}
			pub.Wait()
			close(delivered)
			counts := map[string]int{}
			for kind := range delivered {
				counts[kind]++
			}
			if table == "events" {
				if counts["trace"] != 0 || counts["flag"] != 1 || counts["incident"] != 1 || routed != 2 {
					t.Fatalf("event failure hid independent saved flags or exported failed trace: counts=%v routes=%d", counts, routed)
				}
			} else if counts["trace"] != 1 || counts["flag"] != 0 || counts["incident"] != 0 || routed != 0 {
				t.Fatalf("flag failure exported or routed missing rows: counts=%v routes=%d", counts, routed)
			}
		})
	}
}
