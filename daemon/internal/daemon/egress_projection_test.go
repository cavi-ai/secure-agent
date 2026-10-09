package daemon

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestRejectedEgressProjectionVisibleThroughRecovery(t *testing.T) {
	for _, rejection := range []string{"ABORT, 'injected projection failure'", "IGNORE"} {
		t.Run(rejection, func(t *testing.T) {
			f := newPersistenceFixture(t)
			f.exec(t, `CREATE TRIGGER reject_projection BEFORE INSERT ON egress_episodes BEGIN SELECT RAISE(`+rejection+`); END`)
			a := api.New(api.Deps{Store: f.store, Status: func() api.Status { return api.Status{Running: true} }})
			for _, recovering := range []bool{false, true} {
				if recovering {
					f.exec(t, `DROP TRIGGER reject_projection`)
				}
				deltas, _, health := f.drain(t, event.Event{Kind: event.KindConnOpen, TS: time.Now(), RemoteHost: "api.example.com", RemotePort: 443})
				if len(deltas) != 1 || deltas[0].Type != "event" {
					t.Fatalf("projection failure hid raw event: %+v", deltas)
				}
				if len(health) != 1 {
					t.Fatalf("projection failure/recovery did not refresh posture: %+v", health)
				}
				w := httptest.NewRecorder()
				a.ConsoleHandler().ServeHTTP(w, httptest.NewRequest("GET", "/status", nil))
				var body struct {
					Projection *struct {
						QueueDrops    uint64 `json:"queue_drops"`
						WriteFailures uint64 `json:"write_failures"`
						WriteFailing  bool   `json:"write_failing"`
					} `json:"egress_projection_health"`
					Storage struct {
						Failures uint64 `json:"failures"`
					} `json:"storage_health"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if body.Projection == nil || body.Projection.WriteFailures != 1 || body.Projection.QueueDrops != 0 || body.Projection.WriteFailing == recovering {
					t.Fatalf("projection failure/recovery hidden: %s", w.Body.String())
				}
				if body.Storage.Failures != 0 {
					t.Fatalf("summary loss conflated with evidence loss: %s", w.Body.String())
				}
				w = httptest.NewRecorder()
				a.ConsoleHandler().ServeHTTP(w, httptest.NewRequest("GET", "/posture", nil))
				var posture api.Posture
				if err := json.Unmarshal(w.Body.Bytes(), &posture); err != nil {
					t.Fatal(err)
				}
				if posture.State != "attention" || posture.NeedsYou != 0 || posture.CoverageCount != 1 || posture.CoverageItems[0].Kind != "projection_loss" {
					t.Fatalf("summary gap hidden or mislabeled: %+v", posture)
				}
			}
		})
	}
}

func TestEgressProjectionQueueOverflowDoesNotBlock(t *testing.T) {
	f := newPersistenceFixture(t)
	queue := make(chan store.EgressObservation, 1)
	first := store.EgressObservation{Host: "first.example"}
	if !enqueueEgressProjection(queue, first, f.store) {
		t.Fatal("empty queue rejected observation")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 3; i++ {
			if enqueueEgressProjection(queue, store.EgressObservation{}, f.store) {
				t.Error("full queue accepted observation")
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("projection queue blocked event draining")
	}
	if got := <-queue; got.Host != first.Host {
		t.Fatalf("queued observation overwritten: %+v", got)
	}
	if !enqueueEgressProjection(queue, first, f.store) {
		t.Fatal("queue did not accept after draining")
	}
	h := f.store.EgressProjectionHealth()
	if h.QueueDrops != 3 || h.WriteFailures != 0 || h.WriteFailing || f.store.WriteHealth().Failures != 0 {
		t.Fatalf("incorrect queue loss units: %+v", h)
	}
}
