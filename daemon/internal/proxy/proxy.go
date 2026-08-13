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
	"github.com/cavi-ai/secure-agent/daemon/internal/injection"
	"github.com/cavi-ai/secure-agent/daemon/internal/redact"
)

type ProxyServer struct {
	port      int
	bus       *bus.Bus
	caManager *CAManager
	server    *http.Server
}

func NewProxyServer(port int, b *bus.Bus, caManager *CAManager) *ProxyServer {
	ps := &ProxyServer{
		port:      port,
		bus:       b,
		caManager: caManager,
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

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
	}

	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		_ = tlsClientConn.Close()
		return
	}
	defer tlsClientConn.Close()

	reader := bufio.NewReader(tlsClientConn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	req.URL.Scheme = "https"
	req.URL.Host = r.Host

	// Inspect tunnelled request
	blocked, detail := ps.inspectRequest(req, host)
	if blocked {
		resp := &http.Response{
			StatusCode: http.StatusForbidden,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(fmt.Sprintf(`{"error":"Security Violation","detail":%q}`, detail))),
		}
		_ = resp.Write(tlsClientConn)
		return
	}

	// Forward to target host
	targetConn, err := tls.Dial("tcp", r.Host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		resp := &http.Response{StatusCode: http.StatusBadGateway, ProtoMajor: 1, ProtoMinor: 1}
		_ = resp.Write(tlsClientConn)
		return
	}
	defer targetConn.Close()

	if err := req.Write(targetConn); err != nil {
		return
	}

	targetReader := bufio.NewReader(targetConn)
	resp, err := http.ReadResponse(targetReader, req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Inspect response body for prompt injection
	ps.inspectResponse(resp, host)

	_ = resp.Write(tlsClientConn)
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
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	ps.inspectResponse(resp, host)

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (ps *ProxyServer) inspectRequest(r *http.Request, host string) (blocked bool, detail string) {
	// 1. Inspect headers for secret leaks
	for name, values := range r.Header {
		for _, val := range values {
			if rule, found := redact.Detect(val); found {
				detail = fmt.Sprintf("proxy-secret-leak:%s (header: %s)", rule, name)
				ps.publishHit(host, detail)
				return true, detail
			}
		}
	}

	// 2. Inspect request body for secret leaks
	if r.Body != nil {
		bodyBytes, err := io.ReadAll(r.Body)
		if err == nil {
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			if rule, found := redact.Detect(string(bodyBytes)); found {
				detail = fmt.Sprintf("proxy-secret-leak:%s", rule)
				ps.publishHit(host, detail)
				return true, detail
			}
		}
	}

	return false, ""
}

func (ps *ProxyServer) inspectResponse(resp *http.Response, host string) {
	if resp == nil || resp.Body == nil {
		return
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err == nil {
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		text := string(bodyBytes)
		if rule, found := injection.Detect(text); found {
			detail := fmt.Sprintf("proxy-prompt-injection:%s", rule)
			ps.publishHit(host, detail)
		}
	}
}

func (ps *ProxyServer) publishHit(host, detail string) {
	hostOnly := host
	port := 80
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
