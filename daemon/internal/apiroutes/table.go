// Package apiroutes is the single source of truth for the daemon's HTTP API
// surface. Every route's existence, whether the embedded console may call it
// on the proxy listener, whether it is a mutation, and whether it is the
// agent-facing guard decision live here.
//
// The mux (api.buildMux), the unix-socket peer-role gate (api.authorize) and
// the proxy console allow-list (proxy.isConsoleAPIPath) all read this table.
// Adding an endpoint used to touch three hand-kept lists that drifted; now it
// touches one, and a test asserts the table and the handler map agree.
package apiroutes

import (
	"slices"
	"strings"
)

// Route describes one API endpoint's path and its two derived classifications.
type Route struct {
	// Path is the exact mux pattern. A trailing slash marks a subtree (see
	// Prefix) served by a single handler.
	Path string
	// Prefix marks a dynamic route family matched by path prefix; only the
	// console-admission shape Path + {id} + "/" + one of Leaves is admitted.
	Prefix bool
	// Leaves are the sub-resources a Prefix route serves ("timeline" and
	// "report" for /sessions/{id}/…, "explain" for /flags/{id}/explain).
	Leaves []string
	// Console is true when the console token admits this path on the proxy
	// listener (the browser console's same-origin telemetry surface).
	Console bool
	// MutatingMethods lists the HTTP methods on this path that require the
	// pinned UI (or the owner uid when no UI is pinned). Empty = not a
	// mutation. GET is never a mutation; DELETE stays owner-level (headless
	// fleets revoke over ssh). A method here is also console-admitted (see
	// ConsoleAllowed): the console runs as the pinned UI's own surface, so a
	// mutation it is allowed to trigger it is also allowed to reach directly.
	MutatingMethods []string
	// ConsoleMethods lists non-GET/HEAD methods the console token admits on
	// this path WITHOUT marking them a pinned-UI mutation on the unix socket
	// (unlike MutatingMethods, ConsoleMethods has no effect on authorize/
	// canMutate). Used for the two console-only DELETEs and the two POSTs
	// below that stay owner-level on the socket. Enumerated from every
	// `apiFetch(path, { method: ... })` in web_dist/*.js:
	//   DELETE /mute            app.js:2514 (mute revoke)
	//   DELETE /expected        app.js (forget an expected pattern)
	//   DELETE /allowlist       app.js:2602 (allow revoke)
	//   POST   /notify/rules    app.js:3034, 3060 (notify scope/override)
	//   POST   /advisor/assess-host  app.js:2252 (host reassess)
	//   DELETE /agent/chat      tab-agent.js (clear the conversation)
	//   DELETE /agent/plans     tab-agent.js (delete a plan)
	// Every other (method, path) pair fetched by web_dist/*.js is GET (always
	// admitted) or POST/PUT already covered by MutatingMethods above.
	ConsoleMethods []string
	// Decide marks the agent-facing guard decision endpoint, which uses the
	// weaker canDecide policy instead of canMutate.
	Decide bool
	// OwnerOnly marks a route served only on the unix socket and only to the
	// owner uid (or the pinned UI): never console-admitted, never registered
	// on the proxy listener's handler, refused for agent and foreign peers.
	OwnerOnly bool
	// NoAgent marks a route no agent process may reach: on the unix socket
	// only the owner uid (outside every agent family) and the pinned UI pass;
	// on the console listener the TCP client must be identified and outside
	// every agent family.
	NoAgent bool
}

// Table is the canonical API surface, ordered as registered.
var Table = []Route{
	{Path: "/status", Console: true},
	{Path: "/sessions", Console: true},
	{Path: "/sessions/", Prefix: true, Leaves: []string{"timeline", "report"}, Console: true},
	{Path: "/resources", Console: true},
	{Path: "/resources/episodes", Console: true},
	{Path: "/resources/control", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/resources/policy", Console: true, MutatingMethods: []string{"PUT"}},
	{Path: "/snapshot", Console: true},
	{Path: "/posture", Console: true},
	{Path: "/flags", Console: true},
	{Path: "/flags/", Prefix: true, Leaves: []string{"explain"}, Console: true},
	{Path: "/events", Console: true},
	{Path: "/events/stream", Console: true},
	{Path: "/incidents", Console: true},
	{Path: "/incidents/status", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/audit", Console: true},
	{Path: "/allowlist/suggestions", Console: true},
	{Path: "/allowlist", Console: true, MutatingMethods: []string{"POST"}, ConsoleMethods: []string{"DELETE"}},
	{Path: "/egress/uninspected", Console: true},
	{Path: "/egress/endpoint", Console: true},
	{Path: "/notify/rules", Console: true, ConsoleMethods: []string{"POST"}},
	{Path: "/guard/path-allow", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/mute", Console: true, MutatingMethods: []string{"POST"}, ConsoleMethods: []string{"DELETE"}},
	{Path: "/expected", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}, ConsoleMethods: []string{"DELETE"}},
	{Path: "/advisor/retriage", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/advisor/assess-host", Console: true, ConsoleMethods: []string{"POST"}},
	{Path: "/flags/acknowledge", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/patterns", Console: true},
	{Path: "/ui/open-fda", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/stats/rollup", Console: true},
	{Path: "/costs", Console: true},
	{Path: "/costs/unpriced", Console: true},
	{Path: "/costs/plans", Console: true},
	{Path: "/doctor", Console: true},
	{Path: "/worktrees", Console: true, NoAgent: true},
	{Path: "/worktrees/repos", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/worktrees/remove", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/worktrees/advise", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/worktrees/reveal", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/worktrees/reconnect", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/worktrees/trash", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/cleanup/ledger", Console: true, NoAgent: true},
	{Path: "/worktrees/ask", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/worktrees/asks", Console: true, NoAgent: true},
	{Path: "/cleanup", Console: true, NoAgent: true},
	{Path: "/cleanup/trash", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/cleanup/clean", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/cleanup/advise", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/advisor/discover"},
	{Path: "/fleet", Console: true},
	{Path: "/kill", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/firewall/mode", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/firewall/fingerprints/reload", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/firewall/fingerprints/ingest", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/firewall/sources", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/guard/decision", Decide: true},
	{Path: "/guard/pending", Console: true},
	{Path: "/guard/resolve", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/guard/rules", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/debug/pprof/", Prefix: true, Console: false, OwnerOnly: true},
	{Path: "/files/detail", Console: true, NoAgent: true},
	{Path: "/files/reveal", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/files/open", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/advisor/plan", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/labels", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	// The system agent (console Agent tab): chat, plans and dispatch. NoAgent
	// throughout — a harness dispatch must never be reachable by an agent.
	{Path: "/agent/status", Console: true, NoAgent: true},
	{Path: "/agent/skills", Console: true, NoAgent: true},
	{Path: "/agent/chat", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}, ConsoleMethods: []string{"DELETE"}},
	{Path: "/agent/plans", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}, ConsoleMethods: []string{"DELETE"}},
	{Path: "/agent/dispatch", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/agent/runs", Console: true, NoAgent: true},
}

// ConsoleAllowed reports whether the console token admits (method, path) on
// the proxy listener. Exact table paths are admitted directly; a dynamic
// family (/sessions/{id}/timeline, /sessions/{id}/report, /flags/{id}/explain)
// is admitted only in its exact shape: a non-empty id that is not "." or
// "..", then one of the route's Leaves. GET and HEAD pass on every
// Console: true route; any other method is admitted only when it appears in
// that route's MutatingMethods or ConsoleMethods. Anything else — an unknown
// path, or a method the matched route does not list — falls through to the
// proxy-token challenge.
func ConsoleAllowed(method, path string) bool {
	for _, r := range Table {
		if !r.Console {
			continue
		}
		matched := false
		if r.Prefix {
			if !strings.HasPrefix(path, r.Path) {
				continue
			}
			rest := strings.TrimPrefix(path, r.Path)
			parts := strings.SplitN(rest, "/", 2)
			matched = len(parts) == 2 && parts[0] != "" && parts[0] != "." && parts[0] != ".." && slices.Contains(r.Leaves, parts[1])
		} else {
			matched = r.Path == path
		}
		if !matched {
			continue
		}
		if method == "GET" || method == "HEAD" {
			return true
		}
		return slices.Contains(r.MutatingMethods, method) || slices.Contains(r.ConsoleMethods, method)
	}
	return false
}

// IsMutation reports whether (method, path) is a mutation requiring the pinned
// UI or owner uid.
func IsMutation(method, path string) bool {
	for _, r := range Table {
		if r.Path != path {
			continue
		}
		for _, m := range r.MutatingMethods {
			if m == method {
				return true
			}
		}
		return false
	}
	return false
}

// IsOwnerOnly reports whether path falls under an OwnerOnly route (the
// subtree, or its root without the trailing slash).
func IsOwnerOnly(path string) bool {
	for _, r := range Table {
		if !r.OwnerOnly {
			continue
		}
		if path == r.Path || path == strings.TrimSuffix(r.Path, "/") || (r.Prefix && strings.HasPrefix(path, r.Path)) {
			return true
		}
	}
	return false
}

// IsNoAgent reports whether path is a NoAgent route.
func IsNoAgent(path string) bool {
	for _, r := range Table {
		if r.Path == path {
			return r.NoAgent
		}
	}
	return false
}

// IsDecide reports whether (method, path) is the agent-facing guard decision.
func IsDecide(method, path string) bool {
	if method != "POST" {
		return false
	}
	for _, r := range Table {
		if r.Path == path {
			return r.Decide
		}
	}
	return false
}

// Paths returns the table's paths in order (used by the mux and tests).
func Paths() []string {
	out := make([]string, 0, len(Table))
	for _, r := range Table {
		out = append(out, r.Path)
	}
	return out
}
