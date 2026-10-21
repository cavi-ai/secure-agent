package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// ?types= opens with a ready frame and serves only the named delta types.
func TestEventStreamTypesFilter(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_sse_types_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	hub := NewDeltaHub()
	a := newTestAPI(Deps{SocketPath: sock, Store: testStore(t), Killer: &fakeKiller{}, Status: func() Status { return Status{Running: true} }, Telemetry: TelemetryDeps{DeltaHub: hub}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	req, _ := http.NewRequest("GET", "http://unix/events/stream?types=flag,%20guard-prompt", nil)
	resp, err := unixClient(sock).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	hub.Publish(Delta{Type: "event", Data: event.Event{Kind: event.KindProxyHit, Detail: "unwanted-event"}})
	hub.Publish(Delta{Type: "session", Data: map[string]string{"id": "unwanted-session"}})
	hub.Publish(Delta{Type: "guard-prompt", Data: map[string]string{"id": "wanted-prompt"}})
	hub.Publish(Delta{Type: "flag", Data: map[string]string{"id": "wanted-flag"}})

	buf := make([]byte, 4096)
	deadline := time.Now().Add(3 * time.Second)
	var acc string
	for time.Now().Before(deadline) && !strings.Contains(acc, "wanted-flag") {
		n, err := resp.Body.Read(buf)
		acc += string(buf[:max(n, 0)])
		if err != nil {
			t.Fatalf("stream read: %v (acc=%q)", err, acc)
		}
	}
	ready := strings.Index(acc, "event: ready\n")
	prompt := strings.Index(acc, "event: guard-prompt\n")
	if ready < 0 || prompt < ready || !strings.Contains(acc, "event: flag\n") {
		t.Fatalf("filtered stream = %q, want ready, then guard-prompt and flag", acc)
	}
	if strings.Contains(acc, "unwanted") {
		t.Fatalf("filtered stream carried other types: %q", acc)
	}
}

func TestEventStreamDeliversBusEvents(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_sse_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)

	// Typed deltas: the stream serves the delta hub, not the raw bus.
	hub := NewDeltaHub()

	a := newTestAPI(Deps{SocketPath: sock, Store: testStore(t), Killer: &fakeKiller{}, Status: func() Status { return Status{Running: true} }, Telemetry: TelemetryDeps{DeltaHub: hub}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	req, _ := http.NewRequest("GET", "http://unix/events/stream", nil)
	cl := unixClient(sock)
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content-type = %q", ct)
	}

	hub.Publish(Delta{Type: "event", Data: event.Event{Kind: event.KindProxyHit, PID: 7, Detail: "proxy-secret-leak:aws-key", TS: time.Now()}})

	// Read until we see the event (skipping the initial comment line).
	buf := make([]byte, 4096)
	deadline := time.Now().Add(3 * time.Second)
	var acc string
	for time.Now().Before(deadline) {
		n, err := resp.Body.Read(buf)
		acc += string(buf[:max(n, 0)])
		if strings.Contains(acc, "proxy-secret-leak") {
			break
		}
		if err != nil {
			t.Fatalf("stream read: %v (acc=%q)", err, acc)
		}
	}
	if !strings.Contains(acc, "event: event") || !strings.Contains(acc, "aws-key") {
		t.Fatalf("delta not delivered: %q", acc)
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
