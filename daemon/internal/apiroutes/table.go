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
	// fleets revoke over ssh).
	MutatingMethods []string
	// Decide marks the agent-facing guard decision endpoint, which uses the
	// weaker canDecide policy instead of canMutate.
	Decide bool
	// OwnerOnly marks a route served only on the unix socket and only to the
	// owner uid (or the pinned UI): never console-admitted, never registered
	// on the proxy listener's handler, refused for agent and foreign peers.
	OwnerOnly bool
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
	{Path: "/allowlist", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/egress/uninspected", Console: true},
	{Path: "/egress/endpoint", Console: true},
	{Path: "/notify/rules", Console: true},
	{Path: "/guard/path-allow"},
	{Path: "/mute", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/advisor/retriage", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/advisor/assess-host", Console: true},
	{Path: "/flags/acknowledge", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/patterns", Console: true},
	{Path: "/ui/open-fda", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/stats/rollup", Console: true},
	{Path: "/costs", Console: true},
	{Path: "/costs/unpriced", Console: true},
	{Path: "/doctor", Console: true},
	{Path: "/worktrees", Console: true},
	{Path: "/worktrees/repos", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/worktrees/remove", Console: true, MutatingMethods: []string{"POST"}},
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
}

// ConsoleAllowed reports whether the console token admits path on the proxy
// listener. Exact table paths are admitted directly; a dynamic family
// (/sessions/{id}/timeline, /sessions/{id}/report, /flags/{id}/explain) is
// admitted only in its exact shape: a non-empty id that is not "." or "..",
// then one of the route's Leaves. Anything else falls through to the
// proxy-token challenge.
func ConsoleAllowed(path string) bool {
	for _, r := range Table {
		if !r.Console {
			continue
		}
		if r.Prefix {
			if !strings.HasPrefix(path, r.Path) {
				continue
			}
			rest := strings.TrimPrefix(path, r.Path)
			parts := strings.SplitN(rest, "/", 2)
			if len(parts) == 2 && parts[0] != "" && parts[0] != "." && parts[0] != ".." && slices.Contains(r.Leaves, parts[1]) {
				return true
			}
			continue
		}
		if r.Path == path {
			return true
		}
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
