package inference

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/connpeer"
	"github.com/cavi-ai/secure-agent/daemon/internal/loopback"
	"github.com/cavi-ai/secure-agent/internal/localservice"
)

const maxRequestBody = 16 << 20

// GatewayConfig opts into a separately authenticated model endpoint. The raw
// backend is outside this boundary and must never be represented as isolated.
type GatewayConfig struct {
	Listen     string `yaml:"listen"`
	Upstream   string `yaml:"upstream"`
	APIKeyFile string `yaml:"api_key_file"`
}

func (c GatewayConfig) Validate() error {
	host, port, err := net.SplitHostPort(c.Listen)
	n, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || n < 1 || n > 65535 || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("inference gateway listen must be a literal loopback IP and port")
	}
	u, ok := endpoint(c.Upstream)
	if !ok || (u.Path != "" && u.Path != "/") || u.Port() == strconv.Itoa(n) {
		return errors.New("inference gateway requires a loopback backend on a separate port without a URL path")
	}
	if !filepath.IsAbs(c.APIKeyFile) {
		return errors.New("inference gateway requires an absolute owner-only api_key_file")
	}
	return nil
}

type Gateway struct {
	config   GatewayConfig
	upstream *url.URL
	monitor  *Monitor
	client   *http.Client
	stopping atomic.Bool
	// Identify authenticates a socket's process; client-supplied identity
	// headers are never used for attribution.
	Identify func(context.Context, string) (int32, string)
}

func NewGateway(config GatewayConfig, monitor *Monitor) (*Gateway, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if monitor == nil {
		return nil, errors.New("inference gateway requires an activity monitor")
	}
	upstream, _ := endpoint(config.Upstream)
	request, _ := http.NewRequest(http.MethodGet, upstream.String(), nil)
	if err := localservice.Authorize(request, config.APIKeyFile); err != nil {
		return nil, err
	}
	return &Gateway{config: config, upstream: upstream, monitor: monitor, client: loopback.Client(0)}, nil
}
func (g *Gateway) Serve(ctx context.Context) error {
	g.monitor.GatewayStatus(g.config, "starting")
	listener, err := net.Listen("tcp", g.config.Listen)
	if err != nil {
		g.monitor.GatewayStatus(g.config, "unavailable")
		return err
	}
	defer listener.Close()
	server := &http.Server{Handler: g, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 * 1024, ConnContext: connpeer.WithCache, BaseContext: func(net.Listener) context.Context { return ctx }}
	stop := context.AfterFunc(ctx, func() {
		g.stopping.Store(true)
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		_ = server.Close()
	})
	defer stop()
	g.monitor.GatewayStatus(g.config, "listening")
	err = server.Serve(listener)
	g.monitor.GatewayStatus(g.config, "stopped")
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (g *Gateway) authorized(r *http.Request) bool {
	expected, _ := http.NewRequest(http.MethodGet, g.upstream.String(), nil)
	if localservice.Authorize(expected, g.config.APIKeyFile) != nil {
		return false
	}
	auth, api := r.Header.Values("Authorization"), r.Header.Values("X-Api-Key")
	if len(auth) == 1 && len(api) == 0 {
		return subtle.ConstantTimeCompare([]byte(auth[0]), []byte(expected.Header.Get("Authorization"))) == 1
	}
	if len(api) == 1 && len(auth) == 0 {
		return subtle.ConstantTimeCompare([]byte(api[0]), []byte(strings.TrimPrefix(expected.Header.Get("Authorization"), "Bearer "))) == 1
	}
	return false
}
func (g *Gateway) hostAllowed(host string) bool {
	name, port, err := net.SplitHostPort(host)
	if err != nil {
		return false
	}
	listenHost, listenPort, _ := net.SplitHostPort(g.config.Listen)
	return port == listenPort && (strings.EqualFold(name, "localhost") || name == listenHost)
}
func inferenceRoute(path string) bool {
	switch path {
	case "/api/generate", "/api/chat", "/api/embed", "/api/embeddings", "/v1/chat/completions", "/v1/completions", "/v1/embeddings", "/v1/responses", "/v1/responses/compact", "/v1/messages", "/v1/systemone", "/v1/audio/transcriptions", "/v1/audio/translations", "/v1/audio/speech":
		return true
	}
	return false
}
func metadataRoute(method, path string) bool {
	if method == http.MethodGet {
		switch path {
		case "/api/version", "/api/tags", "/api/ps", "/v1/models":
			return true
		}
		return strings.HasPrefix(path, "/v1/models/") && !strings.Contains(path, "..")
	}
	return method == http.MethodPost && path == "/api/show"
}
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	if !g.hostAllowed(r.Host) || len(r.Header.Values("Origin")) > 0 || r.URL.IsAbs() || r.URL.RawQuery != "" || r.URL.RawPath != "" {
		http.Error(w, "gateway Host and Origin policy refused this request", 403)
		return
	}
	if !g.authorized(r) {
		http.Error(w, "model gateway credential required", 401)
		return
	}
	tracked := r.Method == http.MethodPost && inferenceRoute(r.URL.Path)
	if !tracked && !metadataRoute(r.Method, r.URL.Path) {
		http.Error(w, "model administration is unavailable through this gateway", 403)
		return
	}
	if r.ContentLength > maxRequestBody {
		http.Error(w, "model request exceeds 16 MiB", 413)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Now().Add(15 * time.Second))
	body := http.MaxBytesReader(w, r.Body, maxRequestBody)
	defer body.Close()
	prefix, err := io.ReadAll(io.LimitReader(body, metadataLimit))
	if err != nil {
		http.Error(w, "model request body unavailable", 400)
		return
	}
	model := requestModel(prefix)
	id := ""
	if tracked {
		var pid int32
		sessionID := ""
		if g.Identify != nil {
			pid, sessionID = g.Identify(r.Context(), r.RemoteAddr)
		}
		id, err = g.monitor.begin(g.upstream.String(), r.URL.Path, model, pid, sessionID)
		if err != nil {
			http.Error(w, "model request tracking is at capacity", 503)
			return
		}
	}
	observation := responseObservation{}
	state, status := "interrupted", 0
	defer func() {
		if tracked {
			if g.stopping.Load() {
				state = "interrupted"
			} else if r.Context().Err() != nil {
				state = "cancelled"
			}
			g.monitor.finish(id, state, status, observation)
		}
	}()
	target := *g.upstream
	target.Path = r.URL.Path
	outgoing, err := http.NewRequestWithContext(ctx, r.Method, target.String(), &prefixBody{Reader: io.MultiReader(bytes.NewReader(prefix), body), Closer: body})
	if err != nil {
		http.Error(w, "invalid model request", 400)
		return
	}
	outgoing.ContentLength = r.ContentLength
	outgoing.Header = r.Header.Clone()
	stripHopHeaders(outgoing.Header)
	for _, name := range []string{"Authorization", "X-Api-Key", "Proxy-Authorization", "Cookie", "Origin", "Referer", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host"} {
		outgoing.Header.Del(name)
	}
	response, err := g.client.Do(outgoing)
	if err != nil {
		var maxBytes *http.MaxBytesError
		if errors.As(err, &maxBytes) {
			http.Error(w, "model request exceeds 16 MiB", 413)
		} else {
			http.Error(w, "model backend unavailable", 502)
		}
		return
	}
	defer response.Body.Close()
	status = response.StatusCode
	if status >= 300 && status < 400 {
		state = "failed"
		http.Error(w, "model backend redirect refused", 502)
		return
	}
	stripHopHeaders(response.Header)
	for name, values := range response.Header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "access-control-") || lower == "set-cookie" || lower == "authorization" || lower == "cache-control" {
			continue
		}
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	observation.framed = isFramed(response.Header.Get("Content-Type"))
	w.WriteHeader(status)
	writer := &gatewayWriter{ResponseWriter: w, controller: controller, observation: &observation, monitor: g.monitor, id: id}
	_, err = io.CopyBuffer(writer, response.Body, make([]byte, 32*1024))
	observation.end()
	switch {
	case status >= 400 || observation.failed:
		state = "failed"
	case err != nil || ctx.Err() != nil:
		state = "interrupted"
	case observation.framed && !observation.done:
		state = "interrupted"
	default:
		state = "completed"
	}
}

type gatewayWriter struct {
	http.ResponseWriter
	controller  *http.ResponseController
	observation *responseObservation
	monitor     *Monitor
	id          string
	started     bool
}

func (w *gatewayWriter) Write(data []byte) (int, error) {
	if !w.started {
		w.started = true
		if w.id != "" && w.observation.framed {
			w.monitor.streaming(w.id)
		}
	}
	w.observation.feed(data)
	_ = w.controller.SetWriteDeadline(time.Now().Add(30 * time.Second))
	n, err := w.ResponseWriter.Write(data)
	if err == nil {
		err = w.controller.Flush()
	}
	return n, err
}
func stripHopHeaders(header http.Header) {
	for _, name := range strings.Split(header.Get("Connection"), ",") {
		header.Del(strings.TrimSpace(name))
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		header.Del(name)
	}
}
