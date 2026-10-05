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
		postureCalls, advisorCalls := 0, 0
		done := startDrainLoop(b.Subscribe(), st, correlate.New(tagger, sensitive.New(cfg), cfg), pub,
			session.NewResolver(st, tagger), tagger, hub, nil,
			func() { postureCalls++ }, func() *advisor.Subscriber { advisorCalls++; return nil }, nil)
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
		if flagDeltas != 1 || postureCalls == 0 {
			t.Fatalf("incident failure stalled flag or posture publication: flags=%d posture=%d", flagDeltas, postureCalls)
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
