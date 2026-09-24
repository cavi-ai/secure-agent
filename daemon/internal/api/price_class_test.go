package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// TestPriceClassOnServedEventSurfaces: a model_call row's price class is
// stamped on every surface that serves it — GET /events, /snapshot's
// events, and the SSE delta event frame — never stored (price_class has no
// store column; each surface computes it fresh via collect.EventPriceClass).
func TestPriceClassOnServedEventSurfaces(t *testing.T) {
	st := testStore(t)
	now := time.Now().UTC()
	mc := event.Event{Kind: event.KindModelCall, TS: now, SessionID: "s-1", Model: "claude-sonnet-4-5", TokensIn: 100, TokensOut: 10}
	st.PutEvent(mc)

	a := newTestAPI("", st, &fakeKiller{}, func() Status { return Status{Running: true} })

	// GET /events
	rr := httptest.NewRecorder()
	a.buildMux().ServeHTTP(rr, httptest.NewRequest("GET", "/events", nil))
	if rr.Code != 200 {
		t.Fatalf("GET /events code=%d body=%s", rr.Code, rr.Body.String())
	}
	var evs []event.Event
	if err := json.Unmarshal(rr.Body.Bytes(), &evs); err != nil {
		t.Fatalf("decode /events: %v body=%s", err, rr.Body.String())
	}
	if len(evs) != 1 || evs[0].PriceClass != "priced" {
		t.Fatalf("/events price_class = %+v, want priced", evs)
	}

	// GET /snapshot
	rr2 := httptest.NewRecorder()
	a.buildMux().ServeHTTP(rr2, httptest.NewRequest("GET", "/snapshot", nil))
	if rr2.Code != 200 {
		t.Fatalf("GET /snapshot code=%d body=%s", rr2.Code, rr2.Body.String())
	}
	var snap struct {
		Events []event.Event `json:"events"`
	}
	if err := json.Unmarshal(rr2.Body.Bytes(), &snap); err != nil {
		t.Fatalf("decode /snapshot: %v body=%s", err, rr2.Body.String())
	}
	if len(snap.Events) != 1 || snap.Events[0].PriceClass != "priced" {
		t.Fatalf("/snapshot events price_class = %+v, want priced", snap.Events)
	}

	// SSE/delta event frame: stamped the same way the drain loop does
	// (daemon/internal/daemon/wire.go's startDrainLoop) before publishing.
	sock := fmt.Sprintf("/tmp/sa_test_priceclass_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	a2 := newTestAPI(sock, st, &fakeKiller{}, func() Status { return Status{Running: true} })
	hub := NewDeltaHub()
	a2.deltaHub = hub
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a2.Serve(ctx)
	waitForSocket(t, sock)

	req, _ := http.NewRequest("GET", "http://unix/events/stream", nil)
	cl := unixClient(sock)
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	de := mc
	de.PriceClass = collect.EventPriceClass(mc)
	hub.Publish(Delta{Type: "event", Data: de})

	buf := make([]byte, 4096)
	deadline := time.Now().Add(3 * time.Second)
	var acc string
	for time.Now().Before(deadline) {
		n, rerr := resp.Body.Read(buf)
		acc += string(buf[:max(n, 0)])
		if strings.Contains(acc, "price_class") {
			break
		}
		if rerr != nil {
			t.Fatalf("stream read: %v (acc=%q)", rerr, acc)
		}
	}
	if !strings.Contains(acc, `"price_class":"priced"`) {
		t.Fatalf("SSE delta missing price_class: %q", acc)
	}
}
