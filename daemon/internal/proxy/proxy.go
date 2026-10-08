package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/connpeer"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
	"github.com/cavi-ai/secure-agent/daemon/internal/injection"
)

const (
	// scanCap bounds how many body bytes are buffered for inspection. Bodies are
	// streamed through to the peer; only this prefix is held in memory, so a
	// large or streaming response never buffers in full. Matches the firewall's
	// own per-view normalization cap.
	scanCap = 1 << 20 // 1 MiB
	// dialTimeout bounds the upstream TLS connect so a hung host can't pin a
	// goroutine/fd forever.
	dialTimeout = 10 * time.Second
	// handshakeTimeout bounds the client TLS handshake on a hijacked conn.
	handshakeTimeout = 15 * time.Second
	// idleTunnelTimeout bounds how long a keep-alive CONNECT tunnel waits for the
	// next request before it is torn down.
	idleTunnelTimeout = 90 * time.Second
)

type ProxyServer struct {
	port      atomic.Int32 // written once by Serve if the kernel picked a port
	bus       *bus.Bus
	caManager *CAManager
	engine    *firewall.Engine
	server    *http.Server
	// consoleAPI serves the browser console's telemetry endpoints on this
	// listener, gated by the console token (never the proxy token — agents
	// carry that one). Wired by main via SetConsoleAPI.
	consoleAPI http.Handler
	// plainHTTPClient is shared across plain-HTTP proxy requests so connections
	// are reused; a per-request Transport would defeat keep-alive pooling.
	plainHTTPClient *http.Client
	// inspectHosts are the hosts an inspect-mode CONNECT is decrypted for;
	// every other CONNECT is tunneled. Set once before Serve.
	inspectHosts map[string]bool
	// tunneled and decrypted count CONNECTs by how they were served.
	tunneled    atomic.Uint64
	decrypted   atomic.Uint64
	connMu      sync.Mutex
	connections map[net.Conn]struct{}
	closing     bool
}

// Hijacked connections are no longer owned by http.Server. Registration and
// shutdown share a lock so a concurrent CONNECT cannot escape shutdown.
func (ps *ProxyServer) ownConnection(ctx context.Context, c net.Conn) bool {
	ps.connMu.Lock()
	defer ps.connMu.Unlock()
	if ps.closing || ctx.Err() != nil {
		_ = c.Close()
		return false
	}
	if ps.connections == nil {
		ps.connections = make(map[net.Conn]struct{})
	}
	ps.connections[c] = struct{}{}
	return true
}

func (ps *ProxyServer) releaseConnection(c net.Conn) {
	_ = c.Close()
	ps.connMu.Lock()
	delete(ps.connections, c)
	ps.connMu.Unlock()
}

func (ps *ProxyServer) closeConnections() {
	ps.connMu.Lock()
	ps.closing = true
	connections := ps.connections
	ps.connections = nil
	ps.connMu.Unlock()
	for c := range connections {
		_ = c.Close()
	}
	ps.plainHTTPClient.CloseIdleConnections()
}

// SetInspectHosts sets the hosts an inspect-mode client's CONNECTs are
// decrypted and scanned for. Call before Serve.
func (ps *ProxyServer) SetInspectHosts(hosts []string) {
	m := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			m[h] = true
		}
	}
	ps.inspectHosts = m
}

// inspects reports whether a CONNECT target (host:port) is decrypted for an
// inspect-mode client.
func (ps *ProxyServer) inspects(hostPort string) bool {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
	}
	return ps.inspectHosts[strings.ToLower(host)]
}

// RouteStats counts the CONNECTs the proxy served since start: tunneled
// unopened, and decrypted for inspection.
func (ps *ProxyServer) RouteStats() (tunneled, decrypted uint64) {
	return ps.tunneled.Load(), ps.decrypted.Load()
}

// SetConsoleAPI wires the (ungated-by-peer-creds — this is a TCP listener, so
// the unix-socket peer gate cannot run here) API mux for browser-console
// endpoints. Access is gated by the console token instead.
func (ps *ProxyServer) SetConsoleAPI(h http.Handler) { ps.consoleAPI = h }

func NewProxyServer(port int, b *bus.Bus, caManager *CAManager, engine *firewall.Engine) *ProxyServer {
	ps := &ProxyServer{
		connections: make(map[net.Conn]struct{}),
		bus:         b,
		caManager:   caManager,
		engine:      engine,
	}
	ps.port.Store(int32(port))

	ps.server = &http.Server{
		Addr:              fmt.Sprintf("127.0.0.1:%d", port),
		Handler:           http.HandlerFunc(ps.serveHTTP),
		ReadHeaderTimeout: handshakeTimeout,
		ReadTimeout:       idleTunnelTimeout,
		IdleTimeout:       idleTunnelTimeout,
		ConnState: func(c net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				ps.releaseConnection(c)
			}
		},
		// The console's NoAgent routes cache a successfully identified client
		// process per connection instead of running netstat on every request.
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			ps.ownConnection(ctx, c)
			return connpeer.WithCache(ctx, c)
		},
	}

	ps.plainHTTPClient = &http.Client{
		// Do NOT follow redirects: a 3xx to another host would otherwise be
		// fetched without re-inspection, bypassing host-scoped policy. Return the
		// redirect to the caller instead.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		// Proxy:nil prevents honoring HTTP_PROXY (which agent-env sets to this
		// proxy) and looping the daemon back into itself.
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				c, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				ps.ownConnection(ctx, c)
				return &idleConn{Conn: c, onClose: func() { ps.releaseConnection(c) }}, nil
			},
			ResponseHeaderTimeout: 30 * time.Second,
			TLSHandshakeTimeout:   dialTimeout,
		},
	}

	return ps
}

func (ps *ProxyServer) Port() int {
	return int(ps.port.Load())
}

func (ps *ProxyServer) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", ps.port.Load()))
	if err != nil {
		return fmt.Errorf("failed to listen on proxy port %d: %w", ps.port.Load(), err)
	}
	defer listener.Close()
	return ps.serveListener(ctx, listener)
}

func (ps *ProxyServer) serveListener(ctx context.Context, listener net.Listener) error {
	ctx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	ps.connMu.Lock()
	ps.closing = false
	ps.connMu.Unlock()
	defer ps.closeConnections()
	ps.server.BaseContext = func(net.Listener) context.Context { return ctx }

	if tcpAddr, ok := listener.Addr().(*net.TCPAddr); ok {
		ps.port.Store(int32(tcpAddr.Port))
	}

	errCh := make(chan error, 1)
	go func() {
		if err := ps.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		ps.closeConnections()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return ps.server.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// Refresh per operation so a stalled peer times out while an active stream
// can continue indefinitely.
type idleConn struct {
	net.Conn
	onClose func()
}

func (c *idleConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(idleTunnelTimeout))
	return c.Conn.Read(p)
}
func (c *idleConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(idleTunnelTimeout))
	return c.Conn.Write(p)
}
func (c *idleConn) Close() error {
	if c.onClose != nil {
		c.onClose()
	}
	return c.Conn.Close()
}

func (c *idleConn) CloseWrite() error {
	if tcp, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return tcp.CloseWrite()
	}
	return nil
}

// Preserve bytes buffered by net/http before it handed off a CONNECT.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (ps *ProxyServer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	// The embedded security console is served here so the documented
	// http://127.0.0.1:<proxy_port>/dashboard/ URL actually works; the control
	// API on the unix socket serves the same assets. Everything else on this
	// listener is proxy traffic. The dashboard is browser-reachable and
	// unauthenticated by design (loopback only); all proxy traffic requires
	// the per-install token so the listener is not a free open proxy.
	if r.Method == http.MethodGet && (r.URL.Path == "/dashboard" || strings.HasPrefix(r.URL.Path, "/dashboard/")) {
		serveDashboard(w, r)
		return
	}
	// Browser-console telemetry endpoints. Same-origin fetches from
	// /dashboard/ land on this listener; without this route they got 407 (the
	// proxy token challenge) and the console rendered a permanent offline
	// banner. Gated by the console token — a credential agents do NOT hold,
	// unlike the proxy token they carry for egress.
	if isConsoleAPIPath(r.URL.Path) {
		if ps.consoleAPI == nil || !consoleAuthorized(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"console token required"}`))
			return
		}
		// The path is on the console surface, but the console token does not
		// admit every method on it: GET/HEAD always pass, a mutation only
		// when apiroutes.Table lists it (MutatingMethods or ConsoleMethods).
		// Without this, the console token — issued to the browser, not an
		// owner credential — could reach an owner-level DELETE such as
		// /guard/rules or /guard/path-allow.
		if !apiroutes.ConsoleAllowed(r.Method, r.URL.Path) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"method not permitted for the console token"}`))
			return
		}
		ps.consoleAPI.ServeHTTP(w, r)
		return
	}
	mode, ok := authorize(r)
	if !ok {
		rejectToken(w)
		return
	}
	if r.Method == http.MethodConnect {
		if mode == ModeTunnel || !ps.inspects(r.Host) {
			ps.tunnel(w, r)
			return
		}
		ps.handleConnect(w, r)
		return
	}

	ps.inspectAndForwardHTTP(w, r)
}

// dashboardHeaders are the minimum hardening set for a browser-reachable page
// served from a mixed-traffic listener.
func dashboardHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// no-cache (not no-store): the browser must revalidate every load, so an
	// upgrade can never pair stale cached assets with a new daemon — the
	// "dashboard doesn't load after update" failure mode. Mirrors
	// api.securityHeaders; Last-Modified/304 keeps revalidation cheap.
	w.Header().Set("Cache-Control", "no-cache")
}

func (ps *ProxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, buffered, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if !ps.ownConnection(r.Context(), clientConn) {
		return
	}
	defer ps.releaseConnection(clientConn)

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	tlsCert, err := ps.caManager.GetCertificateForHost(host)
	if err != nil {
		_ = clientConn.Close()
		return
	}

	// Force HTTP/1.1 over the tunnel via ALPN so an HTTP/2-capable client
	// downgrades cleanly instead of speaking a framing this proxy can't parse.
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}

	_ = clientConn.SetDeadline(time.Now().Add(handshakeTimeout))
	tlsClientConn := tls.Server(&bufferedConn{Conn: clientConn, reader: buffered.Reader}, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		_ = tlsClientConn.Close()
		return
	}
	defer tlsClientConn.Close()
	ps.decrypted.Add(1)
	_ = clientConn.SetDeadline(time.Time{})

	// Serve every request on the tunnel, not just the first: real agent clients
	// reuse a keep-alive tunnel for many requests.
	clientIO := &idleConn{Conn: tlsClientConn}
	reader := bufio.NewReader(clientIO)
	for {
		_ = clientConn.SetReadDeadline(time.Now().Add(idleTunnelTimeout))
		req, err := http.ReadRequest(reader)
		if err != nil {
			return // idle timeout, EOF, or client closed the tunnel
		}
		req.URL.Scheme = "https"
		req.URL.Host = r.Host
		req = req.WithContext(r.Context())

		blocked, detail := ps.inspectRequest(req, host)
		if blocked {
			// Drain the (unread) request body before the next ReadRequest:
			// ReadRequest only parses headers, so without draining, the next
			// loop iteration would parse the previous request's body bytes as a
			// new request line and desync the keep-alive tunnel.
			if req.Body != nil {
				_, err = io.Copy(io.Discard, io.LimitReader(req.Body, scanCap+1))
				// Closing on oversized blocked uploads avoids interpreting
				// an undrained suffix as the next HTTP request.
				if err != nil || req.ContentLength > scanCap || req.ContentLength < 0 {
					req.Close = true
				} else {
					req.Body.Close()
				}
			}
			body := fmt.Sprintf(`{"error":"Security Violation","detail":%q}`, detail)
			writeRawResponse(clientIO, http.StatusForbidden, "Forbidden", body, !req.Close)
			if req.Close {
				return
			}
			continue
		}

		keepAlive := ps.forwardConnectRequest(clientIO, req, r.Host, host)
		if req.Body != nil {
			req.Body.Close()
		}
		if !keepAlive || req.Close {
			return
		}
	}
}

// tunnel relays a CONNECT unopened: the client's TLS runs end to end with the
// upstream, so no client needs the proxy CA. The connection is counted; its
// bytes are not read.
func (ps *ProxyServer) tunnel(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	upstream, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(r.Context(), "tcp", r.Host)
	if err != nil {
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	if !ps.ownConnection(r.Context(), upstream) {
		return
	}
	defer ps.releaseConnection(upstream)
	clientConn, buffered, err := hj.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	if !ps.ownConnection(r.Context(), clientConn) {
		return
	}
	defer ps.releaseConnection(clientConn)
	ps.tunneled.Add(1)
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	// Bytes the client sent right behind the CONNECT head are already in the
	// server's reader.
	if n := buffered.Reader.Buffered(); n > 0 {
		head, _ := buffered.Reader.Peek(n)
		if _, err := upstream.Write(head); err != nil {
			return
		}
	}
	done := make(chan error, 2)
	relay := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
		done <- err
	}
	go relay(&idleConn{Conn: upstream}, &idleConn{Conn: clientConn})
	go relay(&idleConn{Conn: clientConn}, &idleConn{Conn: upstream})
	firstErr := <-done
	// An error or idle timeout on either direction ends the whole tunnel.
	if firstErr != nil {
		_ = clientConn.Close()
		_ = upstream.Close()
	}
	<-done
}

// forwardConnectRequest dials the real upstream (verifying its certificate
// against the system roots — skipping that would let a network attacker between
// the proxy and the upstream impersonate the API), relays the request, then
// streams the response back while scanning a bounded prefix. Returns whether the
// tunnel may be reused for another request.
func (ps *ProxyServer) forwardConnectRequest(clientConn net.Conn, req *http.Request, hostPort, host string) bool {
	dialer := &net.Dialer{Timeout: dialTimeout}
	targetConn, err := (&tls.Dialer{NetDialer: dialer, Config: &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}}).DialContext(req.Context(), "tcp", hostPort)
	if err != nil {
		writeRawResponse(clientConn, http.StatusBadGateway, "Bad Gateway", "", false)
		return false
	}
	if !ps.ownConnection(req.Context(), targetConn) {
		return false
	}
	defer ps.releaseConnection(targetConn)
	targetIO := &idleConn{Conn: targetConn}

	if err := req.Write(targetIO); err != nil {
		return false
	}

	targetReader := bufio.NewReader(targetIO)
	resp, err := http.ReadResponse(targetReader, req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if err := ps.streamAndScanResponse(clientConn, resp, host); err != nil {
		return false
	}
	return !resp.Close
}

func (ps *ProxyServer) inspectAndForwardHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}

	blocked, detail := ps.inspectRequest(r, host)
	if blocked {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"error":"Security Violation","detail":%q}`, detail)))
		return
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	outReq.Header = r.Header.Clone()

	resp, err := ps.plainHTTPClient.Do(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	pc := &prefixCapture{cap: scanCap}
	_, _ = io.Copy(idleResponseWriter{w}, io.TeeReader(resp.Body, pc))
	ps.scanForInjection(pc.buf, host)
}

func (ps *ProxyServer) inspectRequest(r *http.Request, host string) (blocked bool, detail string) {
	if ps.engine == nil {
		return false, ""
	}

	hostOnly := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostOnly = h
	}

	// Read only a bounded prefix for inspection, and forward the full body
	// streamed (prefix + remainder) so a large upload never buffers in full.
	var bodyBytes []byte
	if r.Body != nil {
		original := r.Body
		head, err := io.ReadAll(io.LimitReader(original, scanCap+1))
		bodyBytes = head[:min(len(head), scanCap)]
		var tail io.Reader = original
		if err != nil {
			ps.publishHit(host, "proxy-inspection-incomplete:body-read")
			tail = &readError{err: err}
		} else if len(head) > scanCap {
			ps.publishHit(host, "proxy-inspection-incomplete:body-limit")
		}
		r.Body = &replayBody{Reader: io.MultiReader(bytes.NewReader(head), tail), Closer: original}
	}

	headers := make(map[string]string, len(r.Header))
	for name, values := range r.Header {
		headers[name] = strings.Join(values, " ")
	}

	dec := ps.engine.Inspect(firewall.Request{
		Host:           hostOnly,
		Query:          r.URL.RawQuery,
		AuthHeaderName: "authorization",
		Headers:        headers,
		Body:           bodyBytes,
	})

	// Publish every leak (including monitor-mode would-blocks) for observability;
	// only actually block when the resolved action says so.
	for _, f := range dec.Findings {
		if f.Verdict.Kind != firewall.VerdictLeak {
			continue
		}
		d := fmt.Sprintf("proxy-secret-leak:%s", f.Hit.RuleID)
		ps.publishHit(host, d)
		if detail == "" {
			detail = d
		}
	}

	return dec.Action == firewall.ActionBlock, detail
}

// streamAndScanResponse writes resp to dst (streaming the body) while capturing a
// bounded prefix, then scans that prefix for prompt injection over normalized
// views so an encoded payload can't slip past.
func (ps *ProxyServer) streamAndScanResponse(dst io.Writer, resp *http.Response, host string) error {
	pc := &prefixCapture{cap: scanCap}
	resp.Body = &replayBody{Reader: io.TeeReader(resp.Body, pc), Closer: resp.Body}
	err := resp.Write(dst)
	ps.scanForInjection(pc.buf, host)
	return err
}

type replayBody struct {
	io.Reader
	io.Closer
}

type idleResponseWriter struct{ http.ResponseWriter }

func (w idleResponseWriter) Write(p []byte) (int, error) {
	_ = http.NewResponseController(w.ResponseWriter).SetWriteDeadline(time.Now().Add(idleTunnelTimeout))
	return w.ResponseWriter.Write(p)
}

type readError struct{ err error }

func (r *readError) Read([]byte) (int, error) { return 0, r.err }

// scanForInjection runs the injection detector over every normalized view of the
// captured prefix (raw, url-decoded, json-unescaped, base64, gzip), matching the
// secret layer so base64/url/gzip-encoded payloads are not a uniform bypass.
func (ps *ProxyServer) scanForInjection(prefix []byte, host string) {
	if len(prefix) == 0 {
		return
	}
	for _, view := range firewall.Normalize(prefix) {
		if rule, snippet, found := injection.DetectWithSnippet(view); found {
			// The snippet rides in the detail so the flag's evidence (and the
			// advisor's second opinion) shows WHAT matched — bounded and
			// secret-scrubbed by DetectWithSnippet.
			ps.publishHit(host, fmt.Sprintf("proxy-prompt-injection:%s — %q", rule, snippet))
			return
		}
	}
}

// prefixCapture is an io.Writer that keeps at most cap bytes and discards the
// rest, so teeing a large stream through it stays O(cap) in memory.
type prefixCapture struct {
	buf []byte
	cap int
}

func (p *prefixCapture) Write(b []byte) (int, error) {
	if room := p.cap - len(p.buf); room > 0 {
		if room > len(b) {
			room = len(b)
		}
		p.buf = append(p.buf, b[:room]...)
	}
	return len(b), nil
}

// writeRawResponse writes a minimal, well-formed HTTP/1.1 response to a raw conn
// (used inside the CONNECT tunnel where there is no ResponseWriter).
func writeRawResponse(w io.Writer, status int, statusText, body string, keepAlive bool) {
	conn := "close"
	if keepAlive {
		conn = "keep-alive"
	}
	fmt.Fprintf(w,
		"HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: %s\r\n\r\n%s",
		status, statusText, len(body), conn, body)
}

func (ps *ProxyServer) publishHit(host, detail string) {
	hostOnly := host
	port := 443
	if h, pStr, err := net.SplitHostPort(host); err == nil {
		hostOnly = h
		if p, err := strconv.Atoi(pStr); err == nil {
			port = p
		}
	}

	ps.bus.Publish(event.Event{
		Kind:       event.KindProxyHit,
		TS:         time.Now(),
		RemoteHost: hostOnly,
		RemotePort: port,
		Detail:     detail,
	})
}
