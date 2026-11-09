package shellreview

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestClassifierReusesConnections(t *testing.T) {
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, reviewReply)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	defer server.Close()
	s := &Service{cfg: Config{Endpoint: server.URL, TimeoutMS: 1000}}
	for range 2 {
		if _, reason := s.classify(context.Background(), "echo fixture", "/workspace"); reason != "" {
			t.Fatal(reason)
		}
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("two classifications opened %d connections, want one reused connection", got)
	}
}

func TestClassifierLocalhostReachesIPv6OnlyServer(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback unavailable")
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, reviewReply)
	}))
	server.Listener.Close()
	server.Listener = listener
	server.Start()
	defer server.Close()
	s := &Service{cfg: Config{Endpoint: strings.Replace(server.URL, "[::1]", "localhost", 1), TimeoutMS: 1000}}
	if _, reason := s.classify(context.Background(), "echo fixture", "/workspace"); reason != "" {
		t.Fatalf("IPv6 localhost classifier unavailable: %s", reason)
	}
}
