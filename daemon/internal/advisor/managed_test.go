package advisor

import (
	"context"
	"encoding/json"
	"flag"
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

// fakeModelServer re-executes this test binary as a model server, so the
// subprocess test does not depend on an installed Python interpreter.
func fakeModelServer(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell script")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "mlx_lm.server")
	script := "#!/bin/sh\nexport SECURE_AGENT_TEST_MODEL_SERVER=1\nexec '" +
		strings.ReplaceAll(executable, "'", "'\"'\"'") +
		"' -test.run='^TestManagedModelServerHelper$' -- \"$@\"\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func TestManagedModelServerHelper(t *testing.T) {
	if os.Getenv("SECURE_AGENT_TEST_MODEL_SERVER") != "1" {
		return
	}
	if len(os.Args) < 4 || os.Args[2] != "--" {
		t.Fatal("missing managed server arguments")
	}
	args := flag.NewFlagSet("model-server", flag.ContinueOnError)
	model := args.String("model", "", "model ID")
	host := args.String("host", "", "listen address")
	port := args.Int("port", 0, "listen port")
	if err := args.Parse(os.Args[3:]); err != nil {
		t.Fatal(err)
	}
	if *model != "fake-4b" || *host != "127.0.0.1" || *port < 1 || *port > 65535 || args.NArg() != 0 {
		t.Fatalf("invalid managed server arguments: %v", os.Args[3:])
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/models", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]string{{"id": *model}},
		})
	})
	if err := http.ListenAndServe(fmt.Sprintf("%s:%d", *host, *port), mux); err != nil {
		t.Fatal(err)
	}
}

func TestLaunchManagedSpawnsAndServes(t *testing.T) {
	bin := fakeModelServer(t)
	// Launch the helper even when no external runtime is available on PATH.
	t.Setenv("PATH", "")
	cmd, endpoint, err := LaunchManaged(ManagedSpec{Model: "fake-4b", Bin: bin})
	if err != nil {
		t.Fatalf("LaunchManaged: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

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
