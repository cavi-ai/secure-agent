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
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
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
	port      int
	bus       *bus.Bus
	caManager *CAManager
	engine    *firewall.Engine
	server    *http.Server
}

func NewProxyServer(port int, b *bus.Bus, caManager *CAManager, engine *firewall.Engine) *ProxyServer {
	ps := &ProxyServer{
		port:      port,
		bus:       b,
		caManager: caManager,
		engine:    engine,
	}

	ps.server = &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", port),
		Handler: http.HandlerFunc(ps.serveHTTP),
	}

	return ps
}

func (ps *ProxyServer) Port() int {
	return ps.port
}

func (ps *ProxyServer) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", ps.port))
	if err != nil {
		return fmt.Errorf("failed to listen on proxy port %d: %w", ps.port, err)
	}
	defer listener.Close()

	if tcpAddr, ok := listener.Addr().(*net.TCPAddr); ok {
		ps.port = tcpAddr.Port
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
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return ps.server.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

func (ps *ProxyServer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		ps.handleConnect(w, r)
		return
	}

	ps.inspectAndForwardHTTP(w, r)
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

	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

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
	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		_ = tlsClientConn.Close()
		return
	}
	defer tlsClientConn.Close()
	_ = clientConn.SetDeadline(time.Time{})

	// Serve every request on the tunnel, not just the first: real agent clients
	// reuse a keep-alive tunnel for many requests.
	reader := bufio.NewReader(tlsClientConn)
	for {
		_ = clientConn.SetReadDeadline(time.Now().Add(idleTunnelTimeout))
		req, err := http.ReadRequest(reader)
		if err != nil {
			return // idle timeout, EOF, or client closed the tunnel
		}
		_ = clientConn.SetReadDeadline(time.Time{})
		req.URL.Scheme = "https"
		req.URL.Host = r.Host

		blocked, detail := ps.inspectRequest(req, host)
		if blocked {
			body := fmt.Sprintf(`{"error":"Security Violation","detail":%q}`, detail)
			writeRawResponse(tlsClientConn, http.StatusForbidden, "Forbidden", body, !req.Close)
			if req.Close {
				return
			}
			continue
		}

		keepAlive := ps.forwardConnectRequest(tlsClientConn, req, r.Host, host)
		if !keepAlive || req.Close {
			return
		}
	}
}

// forwardConnectRequest dials the real upstream (verifying its certificate
// against the system roots — skipping that would let a network attacker between
// the proxy and the upstream impersonate the API), relays the request, then
// streams the response back while scanning a bounded prefix. Returns whether the
// tunnel may be reused for another request.
func (ps *ProxyServer) forwardConnectRequest(clientConn net.Conn, req *http.Request, hostPort, host string) bool {
	dialer := &net.Dialer{Timeout: dialTimeout}
	targetConn, err := tls.DialWithDialer(dialer, "tcp", hostPort, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		writeRawResponse(clientConn, http.StatusBadGateway, "Bad Gateway", "", false)
		return false
	}
	defer targetConn.Close()

	if err := req.Write(targetConn); err != nil {
		return false
	}

	targetReader := bufio.NewReader(targetConn)
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

	client := &http.Client{
		// Do NOT follow redirects: a 3xx to another host would otherwise be
		// fetched without re-inspection, bypassing host-scoped policy. Return the
		// redirect to the caller instead.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		// Proxy:nil prevents honoring HTTP_PROXY (which agent-env sets to this
		// proxy) and looping the daemon back into itself.
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: dialTimeout}).DialContext,
			ResponseHeaderTimeout: 30 * time.Second,
			TLSHandshakeTimeout:   dialTimeout,
		},
	}

	resp, err := client.Do(outReq)
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
	_, _ = io.Copy(w, io.TeeReader(resp.Body, pc))
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
		head, _ := io.ReadAll(io.LimitReader(r.Body, scanCap))
		bodyBytes = head
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(head), r.Body))
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
	resp.Body = io.NopCloser(io.TeeReader(resp.Body, pc))
	err := resp.Write(dst)
	ps.scanForInjection(pc.buf, host)
	return err
}

// scanForInjection runs the injection detector over every normalized view of the
// captured prefix (raw, url-decoded, json-unescaped, base64, gzip), matching the
// secret layer so base64/url/gzip-encoded payloads are not a uniform bypass.
func (ps *ProxyServer) scanForInjection(prefix []byte, host string) {
	if len(prefix) == 0 {
		return
	}
	for _, view := range firewall.Normalize(prefix) {
		if rule, found := injection.Detect(view); found {
			ps.publishHit(host, fmt.Sprintf("proxy-prompt-injection:%s", rule))
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
