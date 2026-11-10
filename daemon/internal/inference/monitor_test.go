package inference

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/internal/localservice"
)

func TestResidencyAndConnectionsAreNotActiveInference(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			fmt.Fprint(w, `{"version":"0.40.15"}`)
		case "/api/ps":
			fmt.Fprint(w, `{"models":[{"name":"test-model","size":123,"size_vram":100}]}`)
		default:
			t.Errorf("unexpected probe %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	m := New()
	m.Refresh(context.Background(), []string{server.URL}, localservice.Inventory{State: "available"})
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	m.ObserveConnections([]Connection{
		{PID: 123, LocalAddress: "127.0.0.1:50001", RemoteAddress: net.JoinHostPort("127.0.0.1", port)},
		{PID: 123, LocalAddress: "127.0.0.1:50002", RemoteAddress: net.JoinHostPort("127.0.0.1", port)},
		{PID: 456, LocalAddress: "127.0.0.1:50003", RemoteAddress: "127.0.0.1:1"},
	}, "available")
	snapshot := m.Snapshot()
	if len(snapshot.Servers) != 1 || snapshot.Servers[0].Port != p || len(snapshot.Servers[0].Models) != 1 {
		t.Fatalf("servers: %+v", snapshot.Servers)
	}
	if len(snapshot.Connections) != 2 {
		t.Fatalf("connections: %+v", snapshot.Connections)
	}
	if len(snapshot.Requests) != 0 {
		t.Fatalf("passive observations fabricated requests: %+v", snapshot.Requests)
	}
	if snapshot.Coverage.Requests != "routed_only" {
		t.Fatalf("coverage: %+v", snapshot.Coverage)
	}
	m.ObserveConnections(nil, "unavailable")
	if got := m.Snapshot(); got.Coverage.Connections != "unavailable" || len(got.Connections) != 0 {
		t.Fatalf("failed scan hid coverage gap: %+v", got)
	}
}

func TestMetadataCannotRedirectOrLoadAModel(t *testing.T) {
	reached := false
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	defer external.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("metadata generated a request: %s", r.Method)
		}
		http.Redirect(w, r, external.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	m := New()
	m.Refresh(context.Background(), []string{redirect.URL}, localservice.Inventory{State: "partial", Truncated: true})
	if reached {
		t.Fatal("followed a metadata redirect")
	}
	if got := m.Snapshot(); got.Coverage.Discovery != "partial" || !got.Coverage.Truncated {
		t.Fatalf("coverage: %+v", got.Coverage)
	}
}

func TestDiscoveryRotatesPastTheFirstBatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/api/version") {
			fmt.Fprint(w, `{"version":"test"}`)
		} else if strings.HasSuffix(r.URL.Path, "/api/ps") {
			fmt.Fprint(w, `{"models":[]}`)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	targets := []string{}
	for i := 0; i < 20; i++ {
		targets = append(targets, fmt.Sprintf("%s/%d", server.URL, i))
	}
	m := New()
	m.Refresh(context.Background(), targets, localservice.Inventory{State: "available"})
	if got := m.Snapshot(); len(got.Servers) != 16 || got.Coverage.PendingEndpoints != 4 {
		t.Fatalf("first batch: %+v", got)
	}
	m.Refresh(context.Background(), targets, localservice.Inventory{State: "available"})
	if got := m.Snapshot(); len(got.Servers) != 20 {
		t.Fatalf("rotation omitted servers: %d", len(got.Servers))
	}
}
