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

func TestEventStreamDeliversBusEvents(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_sse_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	a := New(sock, testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })

	// Fake bus: subscribe returns a channel we control.
	ch := make(chan event.Event, 4)
	a.SetEventStream(func() <-chan event.Event { return ch },
		func(<-chan event.Event) { close(ch) })
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

	ch <- event.Event{Kind: event.KindProxyHit, PID: 7, Detail: "proxy-secret-leak:aws-key", TS: time.Now()}

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
	if !strings.Contains(acc, "event: proxy-hit") || !strings.Contains(acc, "aws-key") {
		t.Fatalf("event not delivered: %q", acc)
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
