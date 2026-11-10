package inference

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/internal/localservice"
)

func testGateway(t *testing.T, upstream string) (*Monitor, *httptest.Server, string) {
	t.Helper()
	key := filepath.Join(t.TempDir(), "gateway.key")
	if err := localservice.CreateKeyFile(key); err != nil {
		t.Fatal(err)
	}
	m := New()
	server := httptest.NewUnstartedServer(nil)
	g, err := NewGateway(GatewayConfig{Listen: server.Listener.Addr().String(), Upstream: upstream, APIKeyFile: key}, m, RequestPolicy{
		Inspect: func(r *http.Request) error {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				return err
			}
			r.Body = io.NopCloser(strings.NewReader(string(body)))
			return nil
		},
		CheckEgress: func(*http.Request) error { return nil },
	})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	g.Identify = func(context.Context, string) (int32, string) { return 123, "known-session" }
	server.Config.Handler = g
	server.Start()
	t.Cleanup(server.Close)
	return m, server, key
}
func gatewayRequest(t *testing.T, target, key, body string) *http.Request {
	t.Helper()
	r, err := http.NewRequest("POST", target+"/api/chat", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	if err := localservice.Authorize(r, key); err != nil {
		t.Fatal(err)
	}
	return r
}
func TestGatewayTracksStreamingLifetimeAndUsageWithoutPayloads(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Api-Key") != "" {
			t.Error("gateway credential reached backend")
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"model":"test-model","messages":[{"role":"user","content":"PRIVATE-PROMPT"}]}` {
			t.Errorf("request changed: %q", body)
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		fmt.Fprintln(w, `{"model":"test-model","message":{"content":"PRIVATE-ANSWER"},"done":false}`)
		w.(http.Flusher).Flush()
		<-release
		fmt.Fprintln(w, `{"done":true,"prompt_eval_count":12,"eval_count":2}`)
	}))
	defer upstream.Close()
	m, server, key := testGateway(t, upstream.URL)
	response, err := server.Client().Do(gatewayRequest(t, server.URL, key, `{"model":"test-model","messages":[{"role":"user","content":"PRIVATE-PROMPT"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	snapshot := m.Snapshot()
	if len(snapshot.Requests) != 1 || snapshot.Requests[0].State != "streaming" || snapshot.Requests[0].SessionID != "known-session" {
		t.Fatalf("live request: %+v", snapshot.Requests)
	}
	release <- struct{}{}
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "PRIVATE-ANSWER") {
		t.Fatal("response changed")
	}
	got := m.Snapshot().Requests[0]
	if got.State != "completed" || got.InputTokens == nil || *got.InputTokens != 12 || got.OutputTokens == nil || *got.OutputTokens != 2 || got.EndedAt == nil {
		t.Fatalf("completion: %+v", got)
	}
	if got.Model != "test-model" || got.Execution != "unknown" {
		t.Fatalf("model/execution: %+v", got)
	}
}
func TestGatewayRefusesBrowserAdminAndUnsafeKeys(t *testing.T) {
	reached := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached++; fmt.Fprint(w, `{"done":true}`) }))
	defer upstream.Close()
	m, server, key := testGateway(t, upstream.URL)
	for _, kind := range []string{"missing-key", "foreign-origin", "foreign-host", "admin"} {
		r := gatewayRequest(t, server.URL, key, `{"model":"test"}`)
		switch kind {
		case "missing-key":
			r.Header.Del("Authorization")
		case "foreign-origin":
			r.Header.Set("Origin", "https://example.invalid")
		case "foreign-host":
			r.Host = "example.invalid"
		case "admin":
			r.URL.Path = "/api/pull"
		}
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode < 400 {
			t.Fatalf("%s accepted: %d", kind, response.StatusCode)
		}
	}
	if reached != 0 || len(m.Snapshot().Requests) != 0 {
		t.Fatal("refused request reached backend or became inference activity")
	}
	if _, err := NewGateway(GatewayConfig{Listen: "0.0.0.0:12345", Upstream: upstream.URL, APIKeyFile: key}, m, RequestPolicy{}); err == nil {
		t.Fatal("wildcard listener accepted")
	}
	if _, err := NewGateway(GatewayConfig{Listen: "127.0.0.1:12345", Upstream: "http://example.invalid", APIKeyFile: key}, m, RequestPolicy{}); err == nil {
		t.Fatal("non-local backend accepted")
	}
}
func TestGatewayCancellationEndsTheObservedRequest(t *testing.T) {
	stopped := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(stopped)
	}))
	defer upstream.Close()
	m, server, key := testGateway(t, upstream.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	response, err := server.Client().Do(gatewayRequest(t, server.URL, key, `{"model":"test"}`).WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	response.Body.Close()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("backend survived client cancellation")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if r := m.Snapshot().Requests[0]; r.EndedAt != nil {
			if r.State != "cancelled" {
				t.Fatalf("cancellation: %+v", r)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("request remained active after cancellation")
}
