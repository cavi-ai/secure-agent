package proxy

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

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

// consoleAuthorized checks the console token from the X-SecureAgent-Console-Token
// header (fetch/XHR) or the ct query parameter (EventSource can't set headers).
// Constant-time compare, same discipline as the proxy token.
func consoleAuthorized(r *http.Request) bool {
	want := ConsoleToken()
	if want == "" {
		return false // console API disabled (token load failed): fail closed
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-SecureAgent-Console-Token")), []byte(want)) == 1 {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("ct")), []byte(want)) == 1
}

// consoleAPIPaths is the exact endpoint set the embedded console (and only it)
// needs. Everything else on this listener stays proxy traffic.
var consoleAPIPaths = map[string]bool{
	"/status":                       true,
	"/posture":                      true,
	"/flags":                        true,
	"/events":                       true,
	"/events/stream":                true,
	"/incidents":                    true,
	"/incidents/status":             true,
	"/audit":                        true,
	"/fleet":                        true,
	"/firewall/mode":                true,
	"/firewall/sources":             true,
	"/firewall/fingerprints/reload": true,
	"/firewall/fingerprints/ingest": true,
	"/kill":                         true,
	"/guard/pending":                true,
	"/guard/resolve":                true,
	"/guard/rules":                  true,
}

func isConsoleAPIPath(p string) bool { return consoleAPIPaths[p] }
