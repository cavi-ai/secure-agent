// Package loopback keeps local model traffic on this machine.
package loopback

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

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
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
