package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// /fleet serves the live fleet_configured fact while the config watcher
// flips it; run with -race.
func TestFleetConfiguredFollowsTheLiveFact(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	var on atomic.Bool
	a := New(Deps{Store: st, Status: func() Status { return Status{Running: true} }, FleetConfigured: on.Load})
	mux := a.buildMux()
	get := func() bool {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/fleet", nil))
		var node FleetNodeStatus
		if err := json.Unmarshal(rec.Body.Bytes(), &node); err != nil {
			t.Fatalf("GET /fleet: %d %v", rec.Code, err)
		}
		return node.FleetConfigured
	}

	var wg sync.WaitGroup
	var stop atomic.Bool
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			on.Store(i%2 == 0)
		}
	}()
	for i := 0; i < 20; i++ {
		get()
	}
	stop.Store(true)
	wg.Wait()

	on.Store(true)
	if !get() {
		t.Fatal("fleet_configured false while the fact is true")
	}
	on.Store(false)
	if get() {
		t.Fatal("fleet_configured true while the fact is false")
	}
	if New(Deps{Store: st, Status: func() Status { return Status{} }}).fleetConfigured != nil {
		t.Fatal("unwired fact must stay nil")
	}
}

func TestFleetEndpointReturnsNodeStatus(t *testing.T) {
	st := testStore(t)
	sock := fmt.Sprintf("/tmp/sa_test_fleet_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)

	fk := &fakeKiller{}
	statusFn := func() Status {
		return Status{
			Running:      true,
			Uptime:       "1h",
			ActiveAgents: 1,
			Agents: []AgentSummary{
				{PID: 100, Name: "claude", ExePath: "/usr/local/bin/claude", CWD: "/workspace"},
			},
			ProxyEnabled: true,
			ProxyPort:    8443,
		}
	}

	a := newTestAPI(sock, st, fk, statusFn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Get("http://unix/fleet")
	if err != nil {
		t.Fatalf("fleet get: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status=%v", resp.StatusCode)
	}
	defer resp.Body.Close()

	var fleetNode FleetNodeStatus
	if err := json.NewDecoder(resp.Body).Decode(&fleetNode); err != nil {
		t.Fatalf("failed to decode fleet status: %v", err)
	}

	if !fleetNode.Running {
		t.Fatal("fleetNode.Running is false")
	}
	if fleetNode.ActiveAgents != 1 {
		t.Fatalf("fleetNode.ActiveAgents = %d, want 1", fleetNode.ActiveAgents)
	}
	if !fleetNode.ProxyEnabled || fleetNode.ProxyPort != 8443 {
		t.Fatalf("fleetNode proxy info invalid: %v:%d", fleetNode.ProxyEnabled, fleetNode.ProxyPort)
	}
	if fleetNode.Version == "" {
		t.Fatal("fleetNode.Version is empty; build must stamp or default it")
	}
}
