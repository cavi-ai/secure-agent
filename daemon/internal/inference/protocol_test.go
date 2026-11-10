package inference

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func waitRequest(t *testing.T, m *Monitor) Request {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		requests := m.Snapshot().Requests
		if len(requests) > 0 && requests[len(requests)-1].EndedAt != nil {
			return requests[len(requests)-1]
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("request did not finish")
	return Request{}
}
func TestGatewayCompatibleProtocolsAndConnectionReuse(t *testing.T) {
	var accepts atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/embed":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"embeddings":[[0.1]],"prompt_eval_count":3}`)
		case "/v1/chat/completions":
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {\"choices\":[{\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2}}\n\ndata: [DONE]\n\n")
		case "/v1/messages":
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":3}}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":2}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
		case "/v1/responses":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"model":"test","usage":{"input_tokens":3,"output_tokens":2}}`)
		}
	}))
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepts.Add(1)
		}
	}
	upstream.Start()
	defer upstream.Close()
	m, server, key := testGateway(t, upstream.URL)
	for _, path := range []string{"/api/embed", "/v1/chat/completions", "/v1/messages", "/v1/responses"} {
		r := gatewayRequest(t, server.URL, key, `{"model":"test"}`)
		r.URL.Path = path
		if path == "/v1/messages" {
			value := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			r.Header.Del("Authorization")
			r.Header.Set("X-Api-Key", value)
		}
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		got := waitRequest(t, m)
		if got.State != "completed" || got.InputTokens == nil || *got.InputTokens != 3 {
			t.Fatalf("%s: %+v", path, got)
		}
		if path != "/api/embed" && (got.OutputTokens == nil || *got.OutputTokens != 2) {
			t.Fatalf("%s usage: %+v", path, got)
		}
	}
	if accepts.Load() != 1 {
		t.Fatalf("backend used %d connections for four serial requests", accepts.Load())
	}
}
func TestGatewayRefusesBackendRedirectAndKeyPermissionDrift(t *testing.T) {
	var reached atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Store(true) }))
	defer destination.Close()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer backend.Close()
	m, server, key := testGateway(t, backend.URL)
	request := gatewayRequest(t, server.URL, key, `{"model":"test"}`)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	got := waitRequest(t, m)
	if reached.Load() || response.StatusCode != 502 || got.State != "failed" {
		t.Fatalf("redirect reached=%t status=%d state=%s", reached.Load(), response.StatusCode, got.State)
	}
	request = gatewayRequest(t, server.URL, key, `{"model":"test"}`)
	if err := os.Chmod(key, 0644); err != nil {
		t.Fatal(err)
	}
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal("unsafe key file remained usable")
	}
}

type cancelOnHeaderWriter struct {
	*httptest.ResponseRecorder
	cancel context.CancelFunc
}

func (w cancelOnHeaderWriter) WriteHeader(status int) {
	w.ResponseRecorder.WriteHeader(status)
	w.cancel()
}

func TestGatewayKeepsRedirectFailureAfterClientDisconnect(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1", http.StatusTemporaryRedirect)
	}))
	defer backend.Close()
	m, server, key := testGateway(t, backend.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := gatewayRequest(t, server.URL, key, `{"model":"test"}`).WithContext(ctx)
	request.URL.Scheme, request.URL.Host = "", ""
	writer := cancelOnHeaderWriter{ResponseRecorder: httptest.NewRecorder(), cancel: cancel}
	server.Config.Handler.ServeHTTP(writer, request)
	got := waitRequest(t, m)
	if writer.Code != http.StatusBadGateway || got.State != "failed" {
		t.Fatalf("redirect status=%d state=%s", writer.Code, got.State)
	}
}
func TestRequestCapacityAndHistoryStayBounded(t *testing.T) {
	m := New()
	ids := []string{}
	for i := 0; i < maxActiveRequests; i++ {
		id, err := m.begin("http://127.0.0.1:11434", "/api/chat", "test", 1, "")
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if _, err := m.begin("http://127.0.0.1:11434", "/api/chat", "test", 1, ""); err == nil {
		t.Fatal("unbounded concurrent requests")
	}
	for _, id := range ids {
		m.finish(id, "completed", 200, responseObservation{})
	}
	for i := 0; i < maxRequests*2; i++ {
		id, err := m.begin("http://127.0.0.1:11434", "/api/chat", "test", 1, "")
		if err != nil {
			t.Fatal(err)
		}
		m.finish(id, "completed", 200, responseObservation{})
	}
	if len(m.Snapshot().Requests) != maxRequests {
		t.Fatal("unbounded request history")
	}
}
func TestResponseFramingSurvivesOversizedChunksWithoutKeepingPayloads(t *testing.T) {
	observation := responseObservation{framed: true}
	observation.feed([]byte(strings.Repeat("x", metadataLimit+100) + "\n"))
	observation.feed([]byte("{\"done\":true,\"eval_count\":2}\n"))
	observation.end()
	if !observation.partial || !observation.done || observation.output == nil || *observation.output != 2 || len(observation.line) != 0 {
		t.Fatalf("observation: %+v", observation)
	}
}

func TestGatewayCapacityIsReservedBeforeProcessLookup(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	m, server, key := testGateway(t, upstream.URL)
	lookups := 0
	server.Config.Handler.(*Gateway).Identify = func(context.Context, string) (int32, string) { lookups++; return 1, "" }
	for i := 0; i < maxActiveRequests; i++ {
		if !m.reserve() {
			t.Fatal("capacity unavailable")
		}
	}
	defer func() {
		for i := 0; i < maxActiveRequests; i++ {
			m.release()
		}
	}()
	response, err := server.Client().Do(gatewayRequest(t, server.URL, key, `{"model":"test"}`))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 503 || lookups != 0 {
		t.Fatalf("capacity %d, lookups %d", response.StatusCode, lookups)
	}
}
