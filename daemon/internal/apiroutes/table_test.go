package apiroutes

import "testing"

// The console's allow-path action posts /guard/path-allow on the proxy
// listener: the console token admits it, and POST is a pinned-UI mutation.
func TestGuardPathAllowConsoleAdmittedAndMutating(t *testing.T) {
	if !ConsoleAllowed("GET", "/guard/path-allow") {
		t.Fatal("/guard/path-allow must be console-admitted")
	}
	if !IsMutation("POST", "/guard/path-allow") {
		t.Fatal("POST /guard/path-allow must be a mutation")
	}
	for _, m := range []string{"GET", "DELETE"} {
		if IsMutation(m, "/guard/path-allow") {
			t.Fatalf("%s /guard/path-allow must not be a pinned-UI mutation (GET reads, DELETE stays owner-level)", m)
		}
	}
	if ConsoleAllowed("GET", "/guard/path-allow/x") {
		t.Fatal("only the exact path is admitted")
	}
}

// ConsoleAllowed is method-aware: GET/HEAD pass on any Console: true route,
// but a mutating method is admitted only when the matched route lists it in
// MutatingMethods or ConsoleMethods — a route with neither (like /status)
// refuses every other method, and the console-only DELETE/POST additions for
// /mute, /allowlist, /notify/rules and /advisor/assess-host are admitted
// without becoming a pinned-UI mutation on the unix socket.
func TestConsoleAllowedIsMethodAware(t *testing.T) {
	for _, m := range []string{"GET", "HEAD"} {
		if !ConsoleAllowed(m, "/status") {
			t.Errorf("%s /status must be console-admitted (GET/HEAD always pass)", m)
		}
	}
	for _, m := range []string{"POST", "PUT", "DELETE"} {
		if ConsoleAllowed(m, "/status") {
			t.Errorf("%s /status must be refused: no MutatingMethods or ConsoleMethods on that route", m)
		}
	}
	if ConsoleAllowed("DELETE", "/guard/rules") {
		t.Fatal("DELETE /guard/rules must not be console-admitted — owner-level revoke, not the browser console")
	}
	if ConsoleAllowed("DELETE", "/guard/path-allow") {
		t.Fatal("DELETE /guard/path-allow must not be console-admitted — owner-level revoke, not the browser console")
	}
	if !ConsoleAllowed("POST", "/guard/rules") {
		t.Fatal("POST /guard/rules must stay console-admitted")
	}
	if !ConsoleAllowed("PUT", "/resources/policy") {
		t.Fatal("PUT /resources/policy must stay console-admitted")
	}
	if !ConsoleAllowed("DELETE", "/mute") {
		t.Fatal("DELETE /mute must be console-admitted via ConsoleMethods")
	}
	if !ConsoleAllowed("DELETE", "/allowlist") {
		t.Fatal("DELETE /allowlist must be console-admitted via ConsoleMethods")
	}
	if !ConsoleAllowed("POST", "/notify/rules") {
		t.Fatal("POST /notify/rules must be console-admitted via ConsoleMethods")
	}
	if !ConsoleAllowed("POST", "/advisor/assess-host") {
		t.Fatal("POST /advisor/assess-host must be console-admitted via ConsoleMethods")
	}
	// ConsoleMethods is not MutatingMethods: it must not turn these routes
	// into pinned-UI mutations on the unix socket peer gate.
	if IsMutation("DELETE", "/mute") || IsMutation("DELETE", "/allowlist") ||
		IsMutation("POST", "/notify/rules") || IsMutation("POST", "/advisor/assess-host") {
		t.Fatal("ConsoleMethods entries must not become IsMutation on the socket gate")
	}
}
