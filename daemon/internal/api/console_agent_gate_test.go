package api

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
)

const agentRefusal = "agent processes cannot use this endpoint"

// serveConsole runs one request on the console handler. A handler that
// panics on test-sized dependencies still proves the request got past the
// peer gate, so the panic is reported as status 0.
func serveConsole(h http.Handler, method, path string) (code int, body string) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(method, path, strings.NewReader("{}"))
	r.RemoteAddr = "127.0.0.1:50123"
	func() {
		defer func() {
			if recover() != nil {
				w.Code = 0
			}
		}()
		h.ServeHTTP(w, r)
	}()
	return w.Code, w.Body.String()
}

// consoleMutations lists every non-GET/HEAD (method, path) the console token
// admits, in table order.
func consoleMutations(t *testing.T) [][2]string {
	t.Helper()
	var out [][2]string
	for _, r := range apiroutes.Table {
		if !r.Console || r.OwnerOnly {
			continue
		}
		path := r.Path
		if r.Prefix {
			path += "x/" + r.Leaves[0].Path
		}
		for _, m := range append(slices.Clone(r.MutatingMethods), r.ConsoleMethods...) {
			if m == http.MethodGet || m == http.MethodHead {
				continue
			}
			if !apiroutes.ConsoleAllowed(m, path) {
				t.Fatalf("%s %s is listed but not console-admitted", m, path)
			}
			out = append(out, [2]string{m, path})
		}
	}
	return out
}

// An agent that reads the console token must not change guard, firewall,
// allowlist, mute or process state through the console listener.
func TestConsoleMutationsRefuseAgentPeers(t *testing.T) {
	deps := fileTestDeps(t)
	deps.System.TCPClientPID = func(string) (int32, error) { return 777, nil }
	deps.Peers.IsAgentPID = func(pid int32) bool { return pid == 777 }
	h := newTestAPI(deps).ConsoleHandler()
	mutations := consoleMutations(t)
	if len(mutations) < 40 {
		t.Fatalf("only %d console mutations found; the table walk is broken", len(mutations))
	}
	for _, mp := range mutations {
		if code, body := serveConsole(h, mp[0], mp[1]); code != http.StatusForbidden || !strings.Contains(body, agentRefusal) {
			t.Errorf("%s %s from an agent peer: %d %q, want 403", mp[0], mp[1], code, strings.TrimSpace(body))
		}
	}
}

// The gate is about who is asking, not what is asked: a browser peer reaches
// the handler, and reads stay token-only telemetry for every peer.
func TestConsoleMutationGateLetsNonAgentsThrough(t *testing.T) {
	deps := fileTestDeps(t)
	deps.System.TCPClientPID = func(string) (int32, error) { return 777, nil }
	agent := false
	deps.Peers.IsAgentPID = func(int32) bool { return agent }
	h := newTestAPI(deps).ConsoleHandler()
	if code, body := serveConsole(h, http.MethodPost, "/guard/resolve"); code != http.StatusServiceUnavailable || !strings.Contains(body, "guard not enabled") {
		t.Fatalf("browser POST /guard/resolve: %d %q, want the handler's 503", code, body)
	}
	agent = true
	if code, _ := serveConsole(h, http.MethodGet, "/guard/pending"); code == http.StatusForbidden {
		t.Fatal("agent GET /guard/pending refused; reads are not gated")
	}
}

// A peer the daemon cannot identify is refused a mutation with a retryable
// 503, never served.
func TestConsoleMutationGateRefusesUnidentifiedPeers(t *testing.T) {
	deps := fileTestDeps(t)
	deps.System.TCPClientPID = func(string) (int32, error) { return 0, http.ErrNoLocation }
	deps.Peers.IsAgentPID = func(int32) bool { return false }
	h := newTestAPI(deps).ConsoleHandler()
	if code, _ := serveConsole(h, http.MethodPost, "/kill"); code != http.StatusServiceUnavailable {
		t.Fatalf("unidentified POST /kill: %d, want 503", code)
	}
}
