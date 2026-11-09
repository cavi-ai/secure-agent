package advisor

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/cavi-ai/secure-agent/daemon/internal/toolpath"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/internal/modelruntime"
)

// ManagedSpec selects the model served by the owned mlx-agent worker.
// A managed worker never opens a TCP listener or downloads model weights.
type ManagedSpec struct {
	Model string
	// Bin overrides the mlx-agent executable (primarily for isolated tests).
	Bin string
}

const privateProtocol = "inherited-unix-v1"

type managedProcess struct {
	cmd       *exec.Cmd
	transport *http.Transport
	directory string
	once      sync.Once
	exited    chan struct{}
}

func managedBinary(spec ManagedSpec) (ManagedSpec, error) {
	if spec.Bin == "" {
		bin, err := modelruntime.Find()
		if err != nil {
			return spec, fmt.Errorf("mlx-agent is not installed")
		}
		spec.Bin = bin
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := toolpath.Command(ctx, spec.Bin, nil, "serve", "private-worker", "--describe")
	output, err := cmd.Output()
	var capability struct {
		Protocol string `json:"protocol"`
	}
	if err != nil || len(output) > 4096 || json.Unmarshal(output, &capability) != nil || capability.Protocol != privateProtocol {
		return spec, fmt.Errorf("managed analysis requires mlx-agent with the %s private-worker protocol", privateProtocol)
	}
	return spec, nil
}

// LaunchManaged gives mlx-agent an inherited listener inside an owned mode-0700
// directory. Only Unix IPC is allocated; there is no HTTP or raw model TCP port.
func LaunchManaged(spec ManagedSpec) (*managedProcess, error) {
	if spec.Bin == "" {
		var err error
		spec, err = managedBinary(spec)
		if err != nil {
			return nil, err
		}
	}
	directory, err := os.MkdirTemp("/tmp", "sa-model-")
	if err != nil {
		return nil, fmt.Errorf("allocate private model directory: %w", err)
	}
	socketPath := filepath.Join(directory, "model.sock")
	process := &managedProcess{directory: directory, exited: make(chan struct{})}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		process.cleanup()
		return nil, fmt.Errorf("allocate private model listener: %w", err)
	}
	listener.SetUnlinkOnClose(false)
	if err = os.Chmod(socketPath, 0600); err != nil {
		listener.Close()
		process.cleanup()
		return nil, err
	}
	file, err := listener.File()
	listener.Close()
	if err != nil {
		process.cleanup()
		return nil, err
	}
	defer file.Close()
	process.transport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	}, MaxConnsPerHost: 8, IdleConnTimeout: 30 * time.Second}
	cmd := toolpath.Command(context.Background(), spec.Bin, nil, "serve", "private-worker", "--model", spec.Model, "--socket-fd", "3")
	cmd.ExtraFiles = []*os.File{file}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		process.cleanup()
		return nil, fmt.Errorf("start private model worker: %w", err)
	}
	process.cmd = cmd
	log.Printf("advisor: private model worker starting; weights must already be prepared locally")
	return process, nil
}

func (p *managedProcess) cleanup() {
	p.once.Do(func() {
		close(p.exited)
		if p.transport != nil {
			p.transport.CloseIdleConnections()
		}
		_ = os.RemoveAll(p.directory)
	})
}

func (p *managedProcess) waitReady(ctx context.Context, deadline time.Duration) bool {
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	client := &http.Client{Transport: p.transport, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for {
		select {
		case <-p.exited:
			return false
		default:
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1/_mlx/private", nil)
		resp, err := client.Do(req)
		if err == nil {
			ready := resp.StatusCode == http.StatusOK && resp.Header.Get("X-MLX-Agent-Transport") == privateProtocol
			resp.Body.Close()
			if ready {
				return true
			}
		}
		select {
		case <-ctx.Done():
			return false
		case <-p.exited:
			return false
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// DiscoveredServer is one loopback OpenAI-compatible endpoint the user could
// link instead of running a managed one.
type DiscoveredServer struct {
	Endpoint string   `json:"endpoint"` // e.g. "http://127.0.0.1:11434"
	Kind     string   `json:"kind"`     // "ollama" | "openai-compatible"
	Models   []string `json:"models"`
	// Sizes: model name → bytes on disk, from Ollama's /api/tags (other
	// servers do not report sizes).
	Sizes map[string]int64 `json:"sizes,omitempty"`
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
	var sizes map[string]int64
	if port == 11434 {
		kind = "ollama" // Ollama's well-known port; /v1/models is its compat surface
		sizes = ollamaSizes(client, endpoint)
	}
	return &DiscoveredServer{Endpoint: endpoint, Kind: kind, Models: models, Sizes: sizes}
}

// ollamaSizes reads model sizes from Ollama's native /api/tags; nil when it
// does not answer.
func ollamaSizes(client *http.Client, endpoint string) map[string]int64 {
	resp, err := client.Get(endpoint + "/api/tags")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var body struct {
		Models []struct {
			Name string `json:"name"`
			Size int64  `json:"size"`
		} `json:"models"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&body) != nil {
		return nil
	}
	sizes := make(map[string]int64, len(body.Models))
	for _, m := range body.Models {
		sizes[m.Name] = m.Size
	}
	return sizes
}
