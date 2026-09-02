package api

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

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

	a := New(sock, st, fk, statusFn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Get("http://unix/fleet")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("fleet get: %v status=%v", err, resp.StatusCode)
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
