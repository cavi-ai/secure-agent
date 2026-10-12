package advisor

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDiscoverServersFindsOpenAICompatible(t *testing.T) {
	// Stub /v1/models on one of the discover ports... we can't bind fixed
	// ports safely in CI, so test probePort against a random-port stub.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]string{{"id": "qwen3-4b"}, {"id": "llama-3.2-3b"}},
		})
	}))
	defer srv.Close()
	var port int
	fmt.Sscanf(srv.URL[strings.LastIndex(srv.URL, ":")+1:], "%d", &port)

	got := probePort(port)
	if got == nil {
		t.Fatal("expected the stub to be discovered")
	}
	if len(got.Models) != 2 || got.Models[0] != "llama-3.2-3b" { // sorted
		t.Fatalf("models = %v", got.Models)
	}
	if got.Kind != "openai-compatible" && port != 11434 {
		t.Fatalf("kind = %q", got.Kind)
	}
	if got.Endpoint != fmt.Sprintf("http://127.0.0.1:%d", port) {
		t.Fatalf("endpoint = %q", got.Endpoint)
	}
}

func TestDiscoverServersIgnoresNonModelServers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	}))
	defer srv.Close()
	var port int
	fmt.Sscanf(srv.URL[strings.LastIndex(srv.URL, ":")+1:], "%d", &port)
	if got := probePort(port); got != nil {
		t.Fatalf("non-model server must not be discovered: %+v", got)
	}
	if got := probePort(1); got != nil {
		t.Fatal("closed port must not be discovered")
	}
}

// fakeModelServer launches the test binary as a model server, keeping the
// process-launch test independent of an installed Python interpreter.
func fakeModelServer(t *testing.T) string {
	if runtime.GOOS == "windows" {
		t.Skip("shell script")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "mlx_lm.server")
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	quotedBinary := "'" + strings.ReplaceAll(testBinary, "'", "'\"'\"'") + "'"
	script := "#!/bin/sh\nexport SA_ADVISOR_TEST_SERVER=1\nexec " + quotedBinary + " -test.run='^TestManagedModelServerProcess$' -- \"$@\"\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func TestManagedModelServerProcess(t *testing.T) {
	if os.Getenv("SA_ADVISOR_TEST_SERVER") != "1" {
		return
	}
	var port string
	for i, arg := range os.Args {
		if arg == "--port" && i+1 < len(os.Args) {
			port = os.Args[i+1]
			break
		}
	}
	if port == "" {
		t.Fatal("model server helper requires --port")
	}
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "fake-4b"}}})
	})}
	if err := server.Serve(listener); err != nil {
		t.Fatal(err)
	}
}

func TestLaunchManagedSpawnsAndServes(t *testing.T) {
	bin := fakeModelServer(t)
	cmd, endpoint, err := LaunchManaged(ManagedSpec{Model: "fake-4b", Bin: bin})
	if err != nil {
		t.Fatalf("LaunchManaged: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	if !strings.HasPrefix(endpoint, "http://127.0.0.1:") {
		t.Fatalf("endpoint must be loopback, got %q", endpoint)
	}
	// The full race suite runs every package concurrently; process startup can
	// exceed five seconds on a loaded CI host even though the helper is healthy.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if !WaitReady(ctx, endpoint, 15*time.Second) {
		t.Fatal("managed server never became ready")
	}
}

func TestLaunchManagedMissingBinary(t *testing.T) {
	_, _, err := LaunchManaged(ManagedSpec{Model: "x", Bin: "/nonexistent/mlx_lm.server"})
	if err == nil {
		t.Fatal("missing binary must error loudly")
	}
}
