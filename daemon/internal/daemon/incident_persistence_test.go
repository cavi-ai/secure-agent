package daemon

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/fleet"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
	"github.com/cavi-ai/secure-agent/daemon/internal/session"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestDrainLoopIncidentPublicationRequiresPersistence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "events.db")
	st, err := store.Open(dbPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER fail_incidents BEFORE INSERT ON incidents BEGIN SELECT RAISE(ABORT, 'injected incident failure'); END`); err != nil {
		t.Fatal(err)
	}
	var deliveries atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deliveries.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	pub := fleet.NewPublisher()
	pub.AddSink(fleet.NewSink(fleet.WebhookConfig{URL: server.URL, Secret: "[REDACTED]", Events: []string{"incident"}}, "test-node", "test", ""))
	cfg, _ := config.Load("/nonexistent")
	tagger := agents.New(cfg, fakeProcSource{})
	tagger.Refresh()
	now := time.Now()
	for _, recovering := range []bool{false, true} {
		if recovering {
			if _, err := db.Exec("DROP TRIGGER fail_incidents"); err != nil {
				t.Fatal(err)
			}
		}
		hub := api.NewDeltaHub()
		deltas := hub.Subscribe()
		b := bus.New(64)
		var postureCalls atomic.Int32
		advisorCalls := 0
		done := runEventIngest(b.Subscribe(), ingestDeps{Store: st, Correlator: correlate.New(tagger, sensitive.New(cfg), cfg, correlate.Hooks{}), Fleet: pub, Resolver: session.NewResolver(st, tagger), Tagger: tagger, Deltas: hub, PostureChanged: func() { postureCalls.Add(1) }, Advisor: func() *advisor.Subscriber { advisorCalls++; return nil }}).Done()
		b.Publish(event.Event{Kind: event.KindPluginAction, TS: now, PID: 500, Path: "/Users/x/project/.env"})
		b.Publish(event.Event{Kind: event.KindConnOpen, TS: now.Add(time.Millisecond), PID: 500, RemoteHost: "evil.example.com", RemotePort: 443})
		b.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("drain loop did not finish")
		}
		pub.Wait()
		hub.Close()
		var incidentDeltas []model.IncidentReport
		flagDeltas := 0
		for delta := range deltas {
			if delta.Type == "incident" {
				incidentDeltas = append(incidentDeltas, delta.Data.(model.IncidentReport))
			}
			if delta.Type == "flag" {
				flagDeltas++
			}
		}
		if flagDeltas != 1 || postureCalls.Load() == 0 {
			t.Fatalf("incident failure stalled flag or posture publication: flags=%d posture=%d", flagDeltas, postureCalls.Load())
		}
		h := st.WriteHealth()
		if !recovering {
			if len(st.RecentIncidents(10)) != 0 || len(incidentDeltas) != 0 || deliveries.Load() != 0 || advisorCalls != 1 {
				t.Fatalf("unpersisted incident escaped: deltas=%v fleet=%d advisor lookups=%d", incidentDeltas, deliveries.Load(), advisorCalls)
			}
			if h.Failures != 1 || len(h.Active) != 1 || h.Active[0] != "incidents" {
				t.Fatalf("incident failure hidden: %+v", h)
			}
		} else {
			if len(incidentDeltas) != 1 || deliveries.Load() != 1 || advisorCalls != 2 {
				t.Fatalf("recovered incident not published: deltas=%v fleet=%d advisor lookups=%d", incidentDeltas, deliveries.Load(), advisorCalls)
			}
			if saved, err := st.GetIncident(incidentDeltas[0].ID); err != nil || saved.FlagID != incidentDeltas[0].FlagID {
				t.Fatalf("published incident disagrees with storage: %+v, %v", saved, err)
			}
			if h.Failures != 1 || len(h.Active) != 0 {
				t.Fatalf("recovery lost evidence history or retained fault: %+v", h)
			}
		}
		now = now.Add(time.Hour)
	}
}

func TestDrainLoopIncidentLookupFailureDoesNotCreateDuplicate(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "events.db")
	st, err := store.Open(dbPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg, _ := config.Load("/nonexistent")
	tagger := agents.New(cfg, fakeProcSource{})
	tagger.Refresh()
	now := time.Now()
	var incidentID string
	for _, phase := range []string{"initial", "failed", "recovered"} {
		if phase == "failed" {
			// SQLite permits NULL in a TEXT PRIMARY KEY. The stored report
			// still exists, but scanning its identity must fail.
			if _, err := db.Exec(`UPDATE incidents SET id=NULL WHERE id=?`, incidentID); err != nil {
				t.Fatal(err)
			}
		} else if phase == "recovered" {
			if _, err := db.Exec(`UPDATE incidents SET id=? WHERE id IS NULL`, incidentID); err != nil {
				t.Fatal(err)
			}
		}
		hub := api.NewDeltaHub()
		deltas := hub.Subscribe()
		b := bus.New(64)
		var postureCalls atomic.Int32
		done := runEventIngest(b.Subscribe(), ingestDeps{
			Store: st, Correlator: correlate.New(tagger, sensitive.New(cfg), cfg, correlate.Hooks{}),
			Resolver: session.NewResolver(st, tagger), Tagger: tagger, Deltas: hub,
			PostureChanged: func() { postureCalls.Add(1) },
		}).Done()
		b.Publish(event.Event{Kind: event.KindPluginAction, TS: now, PID: 500, Path: "/Users/x/project/.env"})
		b.Publish(event.Event{Kind: event.KindConnOpen, TS: now.Add(time.Millisecond), PID: 500, RemoteHost: "evil.example.com", RemotePort: 443})
		b.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("drain loop did not finish")
		}
		hub.Close()
		var reports []model.IncidentReport
		flags := 0
		for delta := range deltas {
			if delta.Type == "incident" {
				reports = append(reports, delta.Data.(model.IncidentReport))
			} else if delta.Type == "flag" {
				flags++
			}
		}
		if flags != 1 || postureCalls.Load() == 0 {
			t.Fatalf("%s: flag or posture publication stopped: flags=%d posture=%d", phase, flags, postureCalls.Load())
		}
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM incidents`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("%s: lookup created duplicate incidents: count=%d", phase, count)
		}
		if phase == "failed" {
			if len(reports) != 0 {
				t.Fatalf("lookup failure published an incident: %+v", reports)
			}
			health := st.WriteHealth()
			if health.ReadFailures != 1 || len(health.ReadActive) != 1 || health.ReadActive[0] != "incident lookup" {
				t.Fatalf("lookup failure hidden: %+v", health)
			}
		} else {
			if len(reports) != 1 {
				t.Fatalf("%s: expected one persisted incident delta, got %+v", phase, reports)
			}
			if phase == "initial" {
				incidentID = reports[0].ID
			} else if reports[0].ID != incidentID || reports[0].AggregateCount != 2 {
				t.Fatalf("recovery did not aggregate into the original report: %+v", reports[0])
			}
			if phase == "recovered" {
				health := st.WriteHealth()
				if health.ReadFailures != 1 || len(health.ReadActive) != 0 {
					t.Fatalf("lookup health did not recover: %+v", health)
				}
			}
		}
		now = now.Add(time.Hour)
	}
}
