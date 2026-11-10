package inference

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

func TestAReusedPortDoesNotInheritThePreviousModelServer(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	m := New()
	m.servers[server.URL] = Server{Endpoint: server.URL, Runtime: "ollama", PID: 123, Models: []Model{{Name: "previous-model"}}}
	m.Refresh(context.Background(), []string{server.URL}, localservice.Inventory{State: "available", Listeners: []localservice.Listener{{PID: 456, Runtime: "unknown", Endpoint: server.URL}}})
	if got := m.Snapshot(); len(got.Servers) != 0 {
		t.Fatalf("port reuse retained another process's identity: %+v", got.Servers)
	}
}

func TestUnknownListenersRequireExplicitMetadataSelection(t *testing.T) {
	var probes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { probes.Add(1); http.NotFound(w, r) }))
	defer server.Close()
	m := New()
	m.Refresh(context.Background(), []string{"http://127.0.0.1:1"}, localservice.Inventory{State: "available", Listeners: []localservice.Listener{{PID: 456, Runtime: "unknown", Endpoint: server.URL}}})
	if probes.Load() != 0 {
		t.Fatal("automatically probed an unrelated listener")
	}
	if m.Snapshot().Coverage.UnclassifiedListeners != 1 {
		t.Fatal("unclassified listener was hidden")
	}
}

func TestWildcardServerIncludesLoopbackAliasConnections(t *testing.T) {
	m := New()
	m.servers["http://127.0.0.1:11434"] = Server{Endpoint: "http://127.0.0.1:11434", Runtime: "ollama", Binding: "wildcard", Port: 11434}
	m.ObserveConnections([]Connection{{PID: 123, LocalAddress: "127.0.0.1:50001", RemoteAddress: "127.0.0.2:11434"}}, "available")
	if got := m.Snapshot(); len(got.Connections) != 1 || got.Connections[0].Endpoint != "http://127.0.0.2:11434" {
		t.Fatalf("loopback alias missed: %+v", got.Connections)
	}
}

func TestConnectionFreshnessRespectsTheConfiguredSamplingInterval(t *testing.T) {
	m := New(30 * time.Second)
	m.ObserveConnections(nil, "available")
	m.mu.Lock()
	m.coverage.SocketObservedAt = time.Now().Add(-20 * time.Second)
	m.mu.Unlock()
	if m.Snapshot().Coverage.Connections != "available" {
		t.Fatal("a normal sample interval was labelled stale")
	}
}
