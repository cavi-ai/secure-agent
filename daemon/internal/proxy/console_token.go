package proxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
	"github.com/cavi-ai/secure-agent/daemon/internal/safefile"
)

// The console token gates the read/telemetry API surface exposed on the
// proxy's loopback HTTP port (what the browser console at /dashboard/ talks
// to). It is deliberately a DIFFERENT credential from the proxy token:
// agents routed through the proxy legitimately carry the proxy token in
// their environment, and must not be able to turn that into self-approval
// of guard prompts or telemetry reads. Only the menubar (same uid, reads
// the 0600 file) holds the console token.
var consoleToken atomic.Value // string

// LoadConsoleToken returns the per-install console token at path, creating a
// random 128-bit hex token (0600) if none exists. Mirrors LoadToken.
func LoadConsoleToken(path string) string {
	if b, err := os.ReadFile(path); err == nil {
		if t := strings.TrimSpace(string(b)); isHexToken(t) {
			consoleToken.Store(t)
			return t
		}
		log.Printf("proxy: existing console token malformed; regenerating")
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		log.Printf("proxy: random source failed; console API disabled: %v", err)
		return ""
	}
	t := hex.EncodeToString(buf)
	consoleToken.Store(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err == nil {
		if err := safefile.WriteFileAtomic(path, []byte(t+"\n"), 0o600); err != nil {
			log.Printf("proxy: WARNING: console token persist failed: %v", err)
		}
	}
	return t
}

// clearConsoleToken resets auth state; tests use it to isolate the global.
func clearConsoleToken() { consoleToken.Store("") }

// ConsoleToken returns the active console token (empty = console API disabled).
func ConsoleToken() string {
	if v, ok := consoleToken.Load().(string); ok {
		return v
	}
	return ""
}

const (
	consoleTokenHeader = "X-SecureAgent-Console-Token"
	// consoleStreamAuthPath sets the stream cookie: EventSource cannot send
	// the console-token header, and a token in the URL would sit on the
	// request line for the life of the connection.
	consoleStreamAuthPath = "/console/stream-auth"
	consoleStreamPath     = "/events/stream"
	consoleStreamCookie   = "sa_console_stream"
)

// streamCookieValue is derived from the console token and admits only GET
// /events/stream: a leaked cookie authorizes no other request.
func streamCookieValue(token string) string {
	m := hmac.New(sha256.New, []byte(token))
	m.Write([]byte("events-stream"))
	return hex.EncodeToString(m.Sum(nil))
}

// consoleAuthorized checks the console token from the X-SecureAgent-Console-Token
// header, or the stream cookie for GET /events/stream. Constant-time
// compare, same discipline as the proxy token.
func consoleAuthorized(r *http.Request) bool {
	want := ConsoleToken()
	if want == "" {
		return false // console API disabled (token load failed): fail closed
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get(consoleTokenHeader)), []byte(want)) == 1 {
		return true
	}
	if r.Method != http.MethodGet || r.URL.Path != consoleStreamPath {
		return false
	}
	c, err := r.Cookie(consoleStreamCookie)
	return err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(streamCookieValue(want))) == 1
}

// serveStreamAuth answers a header-authenticated POST with the stream cookie.
func serveStreamAuth(w http.ResponseWriter, r *http.Request) {
	want := ConsoleToken()
	if r.Method != http.MethodPost || want == "" ||
		subtle.ConstantTimeCompare([]byte(r.Header.Get(consoleTokenHeader)), []byte(want)) != 1 {
		refuseConsole(w, "console token required")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: consoleStreamCookie, Value: streamCookieValue(want), Path: consoleStreamPath,
		HttpOnly: true, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

// consoleOriginAllowed admits a console request only when its Host names
// this machine's loopback and any Origin is that same host: a page whose DNS
// name was rebound to 127.0.0.1 still sends its own name.
func consoleOriginAllowed(r *http.Request) bool {
	host := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		host = h
	}
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && u.Scheme == "http" && u.Host == r.Host
}

func refuseConsole(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":"` + reason + `"}`))
}

// consoleAPIPaths is the exact endpoint set the embedded console (and only it)
// needs. Everything else on this listener stays proxy traffic.
//
// PARITY: the set is derived from apiroutes.Table (the single source of truth
// shared with the mux and the peer-role gate), so a route is added in exactly
// one place. TestConsoleAPIPathsCoverWebApp still asserts every path the
// console fetches is admitted — a missing path falls through to the
// proxy-token challenge (407) and the panel dies silently.
//
// isConsoleAPIPath answers the PATH question only (does this route belong to
// the console surface at all), using GET as the probe method: GET and HEAD
// pass on every Console: true route, so this is true exactly when some
// Console: true route matches p. serveHTTP uses it to pick the auth realm
// (console token vs. proxy token), then separately checks
// apiroutes.ConsoleAllowed(r.Method, p) to gate the actual method.
func isConsoleAPIPath(p string) bool {
	return apiroutes.ConsoleAllowed("GET", p)
}
