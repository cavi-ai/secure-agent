// Package inference separates server residency, sampled connections and observed
// requests. Passive observations never establish that inference is running.
package inference

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/loopback"
	"github.com/cavi-ai/secure-agent/internal/localservice"
)

const maxServers = 128
const probeBatch = 16
const maxConnections = 2048
const maxRequests = 128

type Model struct {
	Name      string `json:"name"`
	Bytes     int64  `json:"bytes,omitempty"`
	VRAMBytes int64  `json:"vram_bytes,omitempty"`
}
type Server struct {
	Endpoint   string    `json:"endpoint"`
	Runtime    string    `json:"runtime"`
	PID        int       `json:"pid,omitempty"`
	Port       int       `json:"port"`
	Binding    string    `json:"binding"`
	Metadata   string    `json:"metadata"`
	ObservedAt time.Time `json:"observed_at"`
	Models     []Model   `json:"loaded_models"`
}
type Connection struct {
	PID              int32     `json:"pid"`
	Process          string    `json:"process,omitempty"`
	ProcessStartedAt time.Time `json:"process_started_at,omitzero"`
	LocalAddress     string    `json:"local_address"`
	RemoteAddress    string    `json:"remote_address"`
	Endpoint         string    `json:"endpoint"`
	FirstSeen        time.Time `json:"first_seen"`
}
type Request struct {
	ID           string     `json:"id"`
	Endpoint     string     `json:"endpoint"`
	Path         string     `json:"path"`
	Model        string     `json:"model,omitempty"`
	PID          int32      `json:"pid,omitempty"`
	SessionID    string     `json:"session_id,omitempty"`
	State        string     `json:"state"`
	StartedAt    time.Time  `json:"started_at"`
	EndedAt      *time.Time `json:"ended_at,omitempty"`
	HTTPStatus   int        `json:"http_status,omitempty"`
	InputTokens  *int64     `json:"input_tokens,omitempty"`
	OutputTokens *int64     `json:"output_tokens,omitempty"`
	Execution    string     `json:"execution"`
}
type GatewayInfo struct {
	Listen     string `json:"listen"`
	Upstream   string `json:"upstream"`
	State      string `json:"state"`
	Protection string `json:"protection"`
}
type Coverage struct {
	Discovery        string    `json:"discovery"`
	Connections      string    `json:"connections"`
	Requests         string    `json:"requests"`
	Truncated        bool      `json:"truncated"`
	PendingEndpoints int       `json:"pending_endpoints"`
	SocketObservedAt time.Time `json:"socket_observed_at"`
}
type Snapshot struct {
	GeneratedAt time.Time     `json:"generated_at"`
	Coverage    Coverage      `json:"coverage"`
	Servers     []Server      `json:"servers"`
	Connections []Connection  `json:"connections"`
	Requests    []Request     `json:"requests"`
	Gateways    []GatewayInfo `json:"gateways"`
}
type Monitor struct {
	mu          sync.Mutex
	refreshMu   sync.Mutex
	servers     map[string]Server
	connections []Connection
	requests    []Request
	gateways    []GatewayInfo
	coverage    Coverage
	cursor      int
	client      *http.Client
	// Identify supplies process names and birth times without reading arguments.
	Identify func(int32) (string, time.Time)
}

func (m *Monitor) Run(ctx context.Context, configured func() []string) error {
	refresh := func() { m.Refresh(ctx, configured(), localservice.DiscoverListeners(ctx)) }
	refresh()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			refresh()
		}
	}
}

func New() *Monitor {
	return &Monitor{servers: map[string]Server{}, coverage: Coverage{Discovery: "starting", Connections: "starting", Requests: "routed_only"}, client: loopback.Client(600 * time.Millisecond)}
}

func endpoint(raw string) (*url.URL, bool) {
	if len(raw) > 2048 || !loopback.ValidEndpoint(raw) {
		return nil, false
	}
	u, err := url.Parse(raw)
	if err != nil || u.ForceQuery || u.RawPath != "" || strings.ContainsAny(raw, "\r\n\x00") {
		return nil, false
	}
	u.Path = strings.TrimRight(u.Path, "/")
	if u.Port() == "" {
		if u.Scheme == "https" {
			u.Host = net.JoinHostPort(u.Hostname(), "443")
		} else {
			u.Host = net.JoinHostPort(u.Hostname(), "80")
		}
	}
	return u, true
}

// Refresh performs only metadata GETs. It rotates bounded batches so defaults
// cannot indefinitely hide servers on custom ports. It never loads a model.
func (m *Monitor) Refresh(parent context.Context, configured []string, inventory localservice.Inventory) {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()
	candidates := []string{}
	hints := map[string]localservice.Listener{}
	seen := map[string]bool{}
	add := func(raw string) {
		if u, ok := endpoint(raw); ok && !seen[u.String()] {
			seen[u.String()] = true
			candidates = append(candidates, u.String())
		}
	}
	for _, raw := range configured {
		add(raw)
	}
	for _, l := range inventory.Listeners {
		if l.Endpoint != "" && l.Runtime != "unknown" {
			add(l.Endpoint)
		}
	}
	if len(configured) == 0 {
		add("http://127.0.0.1:11434")
	}
	for _, l := range inventory.Listeners {
		if l.Endpoint != "" {
			add(l.Endpoint)
			if u, ok := endpoint(l.Endpoint); ok {
				hints[u.String()] = l
			}
		}
	}
	truncated := inventory.Truncated || len(candidates) > maxServers
	if len(candidates) > maxServers {
		candidates = candidates[:maxServers]
	}
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	count := min(probeBatch, len(candidates))
	results := make([]Server, count)
	slots := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		target := candidates[(m.cursor+i)%len(candidates)]
		wg.Go(func() {
			slots <- struct{}{}
			defer func() { <-slots }()
			results[i] = m.probe(ctx, target, hints[target])
		})
	}
	wg.Wait()
	m.cursor = (m.cursor + count) % max(1, len(candidates))
	m.mu.Lock()
	defer m.mu.Unlock()
	m.coverage.Discovery = inventory.State
	if m.coverage.Discovery == "" {
		m.coverage.Discovery = "unavailable"
	}
	m.coverage.Truncated = truncated
	m.coverage.PendingEndpoints = len(candidates) - count
	for _, s := range results {
		old, known := m.servers[s.Endpoint]
		if s.Runtime == "unknown" {
			if known {
				old.Metadata = s.Metadata
				m.servers[s.Endpoint] = old
			}
			continue
		}
		if s.Metadata != "available" && known {
			old.Metadata = s.Metadata
			m.servers[s.Endpoint] = old
			continue
		}
		m.servers[s.Endpoint] = s
	}
	for key := range m.servers {
		if !seen[key] && inventory.State == "available" {
			delete(m.servers, key)
		}
	}
	if len(m.servers) > maxServers {
		for key := range m.servers {
			if !seen[key] {
				delete(m.servers, key)
			}
		}
	}
}

func (m *Monitor) metadata(ctx context.Context, target, path string, out any) (int, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target+path, nil)
	if err != nil {
		return 0, false
	}
	req.Header.Set("User-Agent", "Secure-Agent-Local-Inference")
	resp, err := m.client.Do(req)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return resp.StatusCode, false
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(data) > 65536 {
		return 200, false
	}
	return 200, json.Unmarshal(data, out) == nil
}
func (m *Monitor) probe(ctx context.Context, target string, hint localservice.Listener) Server {
	u, _ := endpoint(target)
	port, _ := strconv.Atoi(u.Port())
	s := Server{Endpoint: target, Runtime: hint.Runtime, PID: hint.PID, Port: port, Binding: hint.Binding, Metadata: "unavailable", Models: []Model{}}
	if s.Runtime == "" {
		s.Runtime = "unknown"
	}
	if s.Binding == "" {
		s.Binding = "loopback"
	}
	var version struct {
		Version string `json:"version"`
	}
	status, ok := m.metadata(ctx, target, "/api/version", &version)
	if status == 401 || status == 403 {
		s.Metadata = "refused"
		return s
	}
	if ok && version.Version != "" {
		var ps struct {
			Models *[]struct {
				Name string `json:"name"`
				Size int64  `json:"size"`
				VRAM int64  `json:"size_vram"`
			} `json:"models"`
		}
		if _, ok = m.metadata(ctx, target, "/api/ps", &ps); ok && ps.Models != nil {
			s.Runtime, s.Metadata, s.ObservedAt = "ollama", "available", time.Now().UTC()
			for _, model := range *ps.Models {
				if len(s.Models) == 128 {
					break
				}
				s.Models = append(s.Models, Model{Name: bounded(model.Name, 256), Bytes: model.Size, VRAMBytes: model.VRAM})
			}
			return s
		}
	}
	var models struct {
		Data *[]struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if _, ok = m.metadata(ctx, target, "/v1/models", &models); ok && models.Data != nil {
		s.Runtime = "openai-compatible"
		s.Metadata = "available"
		s.ObservedAt = time.Now().UTC()
	}
	return s
}
func bounded(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ObserveConnections records visible client sockets only. A connection is not
// a request, and a failed sample never becomes evidence of inactivity.
func (m *Monitor) ObserveConnections(observed []Connection, state string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	old := map[string]time.Time{}
	for _, c := range m.connections {
		old[connectionKey(c)] = c.FirstSeen
	}
	m.connections = []Connection{}
	seen := map[string]bool{}
	m.coverage.Connections = state
	m.coverage.SocketObservedAt = time.Now().UTC()
	for _, c := range observed {
		if c.PID <= 0 || c.PID == int32(os.Getpid()) {
			continue
		}
		host, port, err := net.SplitHostPort(c.RemoteAddress)
		if err != nil {
			continue
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			continue
		}
		for _, s := range m.servers {
			if port != strconv.Itoa(s.Port) {
				continue
			}
			u, _ := endpoint(s.Endpoint)
			if u.Hostname() != "localhost" && !net.ParseIP(u.Hostname()).Equal(ip) {
				continue
			}
			if m.Identify != nil {
				c.Process, c.ProcessStartedAt = m.Identify(c.PID)
				c.Process = bounded(c.Process, 256)
			}
			if seen[connectionKey(c)] {
				break
			}
			seen[connectionKey(c)] = true
			c.Endpoint = s.Endpoint
			c.FirstSeen = old[connectionKey(c)]
			if c.FirstSeen.IsZero() {
				c.FirstSeen = time.Now().UTC()
			}
			if len(m.connections) >= maxConnections {
				m.coverage.Connections = "partial"
				return
			}
			m.connections = append(m.connections, c)
			break
		}
	}
}
func connectionKey(c Connection) string {
	return strconv.Itoa(int(c.PID)) + "/" + c.ProcessStartedAt.Format(time.RFC3339Nano) + "/" + c.LocalAddress + "/" + c.RemoteAddress
}
func (m *Monitor) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Snapshot{GeneratedAt: time.Now().UTC(), Coverage: m.coverage, Servers: []Server{}, Connections: append([]Connection{}, m.connections...), Requests: append([]Request{}, m.requests...), Gateways: append([]GatewayInfo{}, m.gateways...)}
	for _, server := range m.servers {
		server.Models = append([]Model{}, server.Models...)
		s.Servers = append(s.Servers, server)
	}
	slices.SortFunc(s.Servers, func(a, b Server) int { return strings.Compare(a.Endpoint, b.Endpoint) })
	if s.GeneratedAt.Sub(s.Coverage.SocketObservedAt) > 10*time.Second && s.Coverage.Connections == "available" {
		s.Coverage.Connections = "stale"
	}
	return s
}
