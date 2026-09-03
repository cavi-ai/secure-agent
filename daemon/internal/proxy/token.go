package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// token is the per-install shared secret agents must present to use the
// proxy. Without it, any local process gets free egress through the
// loopback listener — the proxy would be an open proxy for malware that
// cannot otherwise reach the internet cleanly.
//
// The token lives next to the firewall salt (0600) and is embedded in the
// agent-env.sh snippet, which the user sources explicitly. Loopback clients
// that did not opt into routing are unaffected: they don't touch the proxy.
var token atomic.Value // string

// LoadToken returns the per-install proxy token at path, creating a random
// 128-bit hex token (0600) if none exists. Mirrors LoadSalt/LoadNodeID.
func LoadToken(path string) string {
	if b, err := os.ReadFile(path); err == nil {
		if t := strings.TrimSpace(string(b)); isHexToken(t) {
			token.Store(t)
			return t
		}
		log.Printf("proxy: existing token malformed; regenerating")
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		log.Printf("proxy: random source failed; token auth disabled: %v", err)
		return ""
	}
	t := hex.EncodeToString(buf)
	token.Store(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err == nil {
		if err := os.WriteFile(path, []byte(t+"\n"), 0o600); err != nil {
			log.Printf("proxy: token persist failed (token is session-only): %v", err)
		}
	}
	return t
}

// clearProxyToken resets auth state; tests use it to isolate the global.
func clearProxyToken() { token.Store("") }

// Token returns the active token (empty = auth disabled).
func Token() string {
	if v, ok := token.Load().(string); ok {
		return v
	}
	return ""
}

// isHexToken accepts exactly the shape LoadToken generates: 32 hex chars.
func isHexToken(t string) bool {
	if len(t) != 32 {
		return false
	}
	for _, c := range t {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// authorized reports whether the request carries the valid proxy token, in
// either the standard Proxy-Authorization header ("Basic <hex>", base64-free
// by convention here) or the X-SecureAgent-Proxy-Token header (some HTTP
// client stacks strip Proxy-Authorization on CONNECT).
func authorized(r *http.Request) bool {
	want := Token()
	if want == "" {
		return true // auth disabled (token load failed); fail open on loopback
	}
	if r.Header.Get("X-SecureAgent-Proxy-Token") == want {
		return true
	}
	if pa := r.Header.Get("Proxy-Authorization"); strings.HasPrefix(pa, "Basic ") {
		return strings.TrimPrefix(pa, "Basic ") == want
	}
	return false
}

// rejectToken answers 407 with the standard proxy-auth challenge.
func rejectToken(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="secure-agent-proxy"`)
	http.Error(w, "proxy token required — source the agent-env snippet", http.StatusProxyAuthRequired)
}
