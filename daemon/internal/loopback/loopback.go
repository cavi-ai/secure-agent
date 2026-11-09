// Package loopback keeps local model traffic on this machine.
package loopback

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var modelTransport = func() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("invalid local model address")
		}
		hosts := []string{host}
		if strings.EqualFold(host, "localhost") {
			hosts = []string{"127.0.0.1", "::1"}
		}
		for _, literal := range hosts {
			ip := net.ParseIP(literal)
			if ip == nil || !ip.IsLoopback() {
				return nil, errors.New("non-loopback model connection refused")
			}
			var conn net.Conn
			conn, err = (&net.Dialer{Timeout: 300 * time.Millisecond}).DialContext(ctx, network, net.JoinHostPort(literal, port))
			if err == nil {
				return conn, nil
			}
		}
		return nil, err
	}
	return transport
}()

// ValidEndpoint accepts only HTTP model endpoints on a literal loopback
// address or localhost. Credentials, queries and fragments do not belong in
// a model base URL and can change the target when an API path is appended.
func ValidEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Client refuses redirects, including 307/308 redirects that would replay a
// chat POST and its private prompt to a different host.
func Client(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: modelTransport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
