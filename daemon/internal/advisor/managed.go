package advisor

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"time"
)

// managed.go — the two ways the advisor gets a model server without the user
// hand-wiring one:
//
//   - ManagedServer: the daemon spawns and supervises `mlx_lm.server` itself
//     (Path A). Zero user configuration; the download happens inside
//     mlx_lm on first start.
//   - DiscoverServers: probe known loopback ports for OpenAI-compatible
//     servers the user already runs (Path B — Ollama/MLX/llama.cpp).
//
// Both stay loopback-only by construction: managed binds 127.0.0.1, discovery
// only ever dials 127.0.0.1.

// ManagedSpec describes the model server the daemon should run itself.
type ManagedSpec struct {
	Model string // HF id, e.g. "mlx-community/Qwen3-4B-4bit"
	// Bin overrides the mlx_lm.server binary path (tests; defaults to PATH lookup).
	Bin string
}

// DefaultManagedModels is the curated short list the Settings pane offers —
// small enough for a laptop, strong enough for triage JSON.
var DefaultManagedModels = []string{
	"mlx-community/Qwen3-4B-4bit",
	"mlx-community/Llama-3.2-3B-Instruct-4bit",
}

// LaunchManaged starts `mlx_lm.server` for the spec on a free loopback port
// and returns the command (caller supervises it) plus the endpoint to point
// the advisor at. The server downloads the model on first start — readiness
// is the advisor circuit breaker's problem, not a boot blocker.
func LaunchManaged(spec ManagedSpec) (*exec.Cmd, string, error) {
	bin := spec.Bin
	if bin == "" {
		var err error
		bin, err = exec.LookPath("mlx_lm.server")
		if err != nil {
			return nil, "", fmt.Errorf("mlx_lm.server not found on PATH (install with: pip install mlx-lm): %w", err)
		}
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", fmt.Errorf("allocate advisor port: %w", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	// --chat-template-args is off: the advisor's chat request already carries
	// enable_thinking=false per call.
	cmd := exec.Command(bin, "--model", spec.Model, "--host", "127.0.0.1", "--port", fmt.Sprint(port))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, "", fmt.Errorf("start managed model server: %w", err)
	}
	log.Printf("advisor: managed model server starting (model %s, port %d) — first start downloads the model, verdicts begin when ready", spec.Model, port)
	return cmd, fmt.Sprintf("http://127.0.0.1:%d", port), nil
}

// WaitReady polls the managed server's /v1/models until it answers or the
// deadline passes. Used so status/reporting can distinguish "downloading"
// from "serving".
func WaitReady(ctx context.Context, endpoint string, deadline time.Duration) bool {
	deadlineAt := time.Now().Add(deadline)
	for time.Now().Before(deadlineAt) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v1/models", nil)
		if err == nil {
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return true
				}
			}
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(500 * time.Millisecond):
		}
	}
	return false
}

// DiscoveredServer is one loopback OpenAI-compatible endpoint the user could
// link instead of running a managed one.
type DiscoveredServer struct {
	Endpoint string   `json:"endpoint"` // e.g. "http://127.0.0.1:11434"
	Kind     string   `json:"kind"`     // "ollama" | "openai-compatible"
	Models   []string `json:"models"`
}

// discoverPorts are the loopback ports probed, most common first: Ollama,
// mlx_lm default, the dogfood-adjacent alternates, LM Studio.
var discoverPorts = []int{11434, 8080, 8799, 8081, 1234}

// DiscoverServers probes the known loopback ports with a tight per-port
// budget. It never blocks long (discovery renders a settings dropdown) and
// never dials anything but 127.0.0.1.
func DiscoverServers() []DiscoveredServer {
	type result struct {
		port int
		srv  *DiscoveredServer
	}
	ch := make(chan result, len(discoverPorts))
	for _, port := range discoverPorts {
		go func(p int) {
			ch <- result{p, probePort(p)}
		}(port)
	}
	found := map[int]*DiscoveredServer{}
	for range discoverPorts {
		r := <-ch
		if r.srv != nil {
			found[r.port] = r.srv
		}
	}
	out := make([]DiscoveredServer, 0, len(found))
	for _, p := range discoverPorts { // stable order: probe priority
		if s := found[p]; s != nil {
			out = append(out, *s)
		}
	}
	return out
}

func probePort(port int) *DiscoveredServer {
	endpoint := fmt.Sprintf("http://127.0.0.1:%d", port)
	client := &http.Client{Timeout: 400 * time.Millisecond}
	resp, err := client.Get(endpoint + "/v1/models")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var body struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || len(body.Data) == 0 {
		return nil
	}
	models := make([]string, 0, len(body.Data))
	for _, m := range body.Data {
		if m.ID != "" {
			models = append(models, m.ID)
		}
	}
	sort.Strings(models)
	kind := "openai-compatible"
	if port == 11434 {
		kind = "ollama" // Ollama's well-known port; /v1/models is its compat surface
	}
	return &DiscoveredServer{Endpoint: endpoint, Kind: kind, Models: models}
}
