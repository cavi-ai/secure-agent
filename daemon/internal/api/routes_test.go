package api

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
)

// The mux, the peer-role gate and the console allow-list all read
// apiroutes.Table. This is the test that makes them unable to drift: every
// table path has a handler, and every handler map entry is in the table.
func TestRouteTableMatchesHandlers(t *testing.T) {
	a := newTestAPI("", testStore(t), nil, func() Status { return Status{Running: true} })
	handlers := a.routes()

	var missingHandler, missingRoute []string
	for _, r := range apiroutes.Table {
		if _, ok := handlers[r.Path]; !ok {
			missingHandler = append(missingHandler, r.Path)
		}
	}
	inTable := map[string]bool{}
	for _, r := range apiroutes.Table {
		inTable[r.Path] = true
	}
	for p := range handlers {
		if !inTable[p] {
			missingRoute = append(missingRoute, p)
		}
	}
	sort.Strings(missingHandler)
	sort.Strings(missingRoute)
	if len(missingHandler) > 0 {
		t.Errorf("table paths with no handler (the mux would skip them silently): %v", missingHandler)
	}
	if len(missingRoute) > 0 {
		t.Errorf("handlers absent from apiroutes.Table (unreachable from the console or gate): %v", missingRoute)
	}
}

// Every table route must actually answer on the mux — a route registered in the
// table but not the mux would be a silent hole, and this catches the reverse of
// the check above at the HTTP layer.
func TestRouteTablePathsAreRegistered(t *testing.T) {
	a := newTestAPI("", testStore(t), nil, func() Status { return Status{Running: true} })
	mux := a.buildMux()
	for _, r := range apiroutes.Table {
		// A GET to a mutation still proves the path is routed (it returns 405
		// or a domain error, never the mux's 404 for an unknown path).
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, r.Path, nil))
		if rec.Code == http.StatusNotFound && rec.Body.String() == "404 page not found\n" {
			t.Errorf("table route %s is not registered on the mux", r.Path)
		}
	}
}

// The console allow-list and the table must agree exactly: a path admitted by
// the console must be a real route, and a console-facing route must be
// admitted (otherwise the panel 407s on the proxy listener).
func TestConsoleAllowListMatchesTable(t *testing.T) {
	for _, r := range apiroutes.Table {
		if r.Prefix {
			continue // dynamic family, shape-checked separately
		}
		if r.Console && !apiroutes.ConsoleAllowed(r.Path) {
			t.Errorf("route %s is console-facing but not admitted", r.Path)
		}
		if !r.Console && apiroutes.ConsoleAllowed(r.Path) {
			t.Errorf("route %s is admitted to the console but not marked console-facing", r.Path)
		}
	}
	// The guard decision endpoint is agent-facing and must never be admitted.
	if apiroutes.ConsoleAllowed("/guard/decision") {
		t.Error("/guard/decision must not be reachable with the console token")
	}
}

// The owner-only profiling routes are never admitted by the console token.
func TestConsoleAllowListRejectsPprof(t *testing.T) {
	for _, p := range []string{"/debug/pprof/", "/debug/pprof", "/debug/pprof/heap", "/debug/pprof/profile"} {
		if apiroutes.ConsoleAllowed(p) {
			t.Errorf("%s is admitted to the console", p)
		}
		if !apiroutes.IsOwnerOnly(p) {
			t.Errorf("%s is not owner-only", p)
		}
	}
// The flag explanation is a dynamic /flags/{id}/explain family: the console
// admits exactly that shape, and the exact acknowledge route keeps its gate.
func TestFlagExplainRouteGate(t *testing.T) {
	if !apiroutes.ConsoleAllowed("/flags/abc/explain") {
		t.Fatal("/flags/{id}/explain must be console-allowed")
	}
	for _, p := range []string{"/flags/../explain", "/flags/./explain", "/flags//explain", "/flags/abc", "/flags/abc/timeline",
		"/flags/abc/explain/x", "/sessions/abc/explain", "/flags/"} {
		if apiroutes.ConsoleAllowed(p) {
			t.Errorf("ConsoleAllowed(%q) = true, want false", p)
		}
	}
	if !apiroutes.ConsoleAllowed("/sessions/abc/timeline") || apiroutes.ConsoleAllowed("/sessions/../timeline") {
		t.Error("session timeline shape changed")
	}
	if !apiroutes.ConsoleAllowed("/flags/acknowledge") || !apiroutes.ConsoleAllowed("/flags") {
		t.Error("exact /flags routes must stay console-allowed")
	}
	if !apiroutes.IsMutation("POST", "/flags/acknowledge") {
		t.Error("POST /flags/acknowledge must stay a mutation")
	}
	if apiroutes.IsMutation("GET", "/flags/abc/explain") || apiroutes.IsMutation("POST", "/flags/abc/explain") {
		t.Error("the explain route is a read")
	}
}
