package advisor

import (
	"context"
	"encoding/json"
	"fmt"
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

// fakeModelServer writes a tiny executable shell script that behaves like
// mlx_lm.server enough for LaunchManaged: parse --port, serve /v1/models.
func fakeModelServer(t *testing.T) string {
	if runtime.GOOS == "windows" {
		t.Skip("shell script")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "mlx_lm.server")
	script := `#!/bin/sh
port=8080
while [ $# -gt 0 ]; do
  if [ "$1" = "--port" ]; then port=$2; shift 2; continue; fi
  shift
done
exec python3 -c "
import http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({'data': [{'id': 'fake-4b'}]}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
http.server.HTTPServer(('127.0.0.1', $port), H).serve_forever()
"
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func TestLaunchManagedSpawnsAndServes(t *testing.T) {
	bin := fakeModelServer(t)
	cmd, endpoint, err := LaunchManaged(ManagedSpec{Model: "fake-4b", Bin: bin})
	if err != nil {
		t.Fatalf("LaunchManaged: %v", err)
	}
	defer cmd.Process.Kill()

	if !strings.HasPrefix(endpoint, "http://127.0.0.1:") {
		t.Fatalf("endpoint must be loopback, got %q", endpoint)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !WaitReady(ctx, endpoint, 5*time.Second) {
		t.Fatal("managed server never became ready")
	}
}

func TestLaunchManagedMissingBinary(t *testing.T) {
	_, _, err := LaunchManaged(ManagedSpec{Model: "x", Bin: "/nonexistent/mlx_lm.server"})
	if err == nil {
		t.Fatal("missing binary must error loudly")
	}
}
