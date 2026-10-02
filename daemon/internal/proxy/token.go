package proxy

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/cavi-ai/secure-agent/daemon/internal/agentenv"
	"github.com/cavi-ai/secure-agent/daemon/internal/safefile"
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
		if err := safefile.WriteFileAtomic(path, []byte(t+"\n"), 0o600); err != nil {
			log.Printf("proxy: WARNING: token persist failed (token is session-only; sourced agent-env snippets will desync on restart): %v", err)
		}
	}
	return t
}

// clearProxyToken resets auth state; tests use it to isolate the global.
func clearProxyToken() { token.Store("") }

// Token returns the active token (empty = load failed; auth fails closed).
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

// Mode is what a routed client asked the proxy for, by the user name in its
// proxy URL (http://<mode>:<token>@127.0.0.1:<port>).
type Mode int

const (
	// ModeInspect decrypts and scans connections to the inspect hosts and
	// tunnels the rest; the client must trust the proxy CA for those hosts.
	ModeInspect Mode = iota
	// ModeTunnel passes every connection through unopened: the destination
	// is recorded, the bytes are not, and no client needs the proxy CA.
	ModeTunnel
)

// authorize reports whether the request carries the valid proxy token and
// which mode it asked for. Accepted: Proxy-Authorization "Basic
// base64(<user>:<token>)", which clients send for credentials in the proxy
// URL (user agentenv.TunnelUser selects ModeTunnel); the raw "Basic <token>"
// form; and the X-SecureAgent-Proxy-Token header (some HTTP client stacks
// strip Proxy-Authorization on CONNECT). The raw forms carry no user name and
// inspect. Comparison is constant-time — even on loopback, a timing oracle on
// the auth gate of a security tool is not a class of bug to ship.
func authorize(r *http.Request) (Mode, bool) {
	want := Token()
	if want == "" {
		// Fail closed: a missing token means the random source failed at
		// startup. An open relay on a security product's egress proxy is
		// worse than a broken one — matches consoleAuthorized.
		return ModeInspect, false
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-SecureAgent-Proxy-Token")), []byte(want)) == 1 {
		return ModeInspect, true
	}
	pa, ok := strings.CutPrefix(r.Header.Get("Proxy-Authorization"), "Basic ")
	if !ok {
		return ModeInspect, false
	}
	if subtle.ConstantTimeCompare([]byte(pa), []byte(want)) == 1 {
		return ModeInspect, true
	}
	decoded, err := base64.StdEncoding.DecodeString(pa)
	if err != nil {
		return ModeInspect, false
	}
	user, pass, found := strings.Cut(string(decoded), ":")
	if !found || subtle.ConstantTimeCompare([]byte(pass), []byte(want)) != 1 {
		return ModeInspect, false
	}
	if user == agentenv.TunnelUser {
		return ModeTunnel, true
	}
	return ModeInspect, true
}

// rejectToken answers 407 with the standard proxy-auth challenge.
func rejectToken(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="secure-agent-proxy"`)
	http.Error(w, "proxy token required — source the agent-env snippet", http.StatusProxyAuthRequired)
}
