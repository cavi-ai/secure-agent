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

//go:generate go run ../../cmd/genroutes -out ../api/routes_generated.go

// Leaf describes one dynamic sub-resource and its typed binding. Empty Handler
// means the family handler performs its own ID validation and dispatch.
type Leaf struct {
	Path     string
	Handler  string
	Response string
}

// Route describes one API endpoint's path and its two derived classifications.
type Route struct {
	// Handler names an API method (API.name) or a package-level handler.
	Handler string
	// Response names a Go wire type; empty for streams or dynamic envelopes.
	Response string
	// Path is the exact mux pattern. A trailing slash marks a subtree (see
	// Prefix) served by a single handler.
	Path string
	// Prefix marks a dynamic route family matched by path prefix; only the
	// console-admission shape Path + {id} + "/" + one of Leaves is admitted.
	Prefix bool
	// Leaves are the sub-resources a Prefix route serves ("timeline", "report",
	// and "memory" for /sessions/{id}/…, "explain" for /flags/{id}/explain).
	Leaves []Leaf
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
	{Path: "/status", Handler: "API.handleStatus", Response: "api.Status", Console: true},
	{Path: "/sessions", Handler: "API.handleSessions", Response: "[]model.Session", Console: true},
	{Path: "/sessions/", Handler: "API.handleSessionSubpath", Prefix: true, Leaves: []Leaf{{Path: "timeline", Handler: "serveSessionTimeline", Response: "[]event.Event"}, {Path: "report", Handler: "serveSessionReport", Response: "store.SessionReport"}, {Path: "memory", Handler: "serveSessionMemory", Response: "api.memoryResponse"}, {Path: "overview", Handler: "serveSessionOverview", Response: "api.SessionOverview"}, {Path: "outcomes", Handler: "serveSessionOutcomes", Response: "api.SessionOutcomes"}}, Console: true},
	{Path: "/resources", Handler: "API.handleResources", Response: "resource.Snapshot", Console: true},
	{Path: "/resources/episodes", Handler: "API.handleResourceEpisodes", Console: true},
	{Path: "/resources/control", Handler: "API.handleResourceControl", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/resources/policy", Handler: "API.handleResourcePolicy", Console: true, MutatingMethods: []string{"PUT"}},
	{Path: "/snapshot", Handler: "API.handleSnapshot", Response: "api.Snapshot", Console: true},
	{Path: "/posture", Handler: "API.handlePosture", Response: "api.Posture", Console: true},
	{Path: "/flags", Handler: "API.handleFlags", Response: "[]model.Flag", Console: true},
	{Path: "/reviews", Handler: "API.handleReviews", Response: "store.ReviewPage", Console: true, NoAgent: true},
	{Path: "/reviews/decision", Handler: "API.handleReviewDecision", Response: "model.ReviewDecisionReceipt", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/decision-scopes", Handler: "API.handleDecisionScopes", Console: true, NoAgent: true, MutatingMethods: []string{"DELETE"}, ConsoleMethods: []string{"GET", "DELETE"}},
	{Path: "/flags/", Handler: "API.handleFlagExplain", Prefix: true, Leaves: []Leaf{{Path: "explain", Response: "model.Flag"}}, Console: true},
	{Path: "/events", Handler: "API.handleEvents", Response: "[]event.Event", Console: true},
	{Path: "/events/stream", Handler: "API.handleEventStream", Console: true},
	{Path: "/incidents", Handler: "API.handleIncidents", Console: true},
	{Path: "/incidents/status", Handler: "API.handleIncidentStatus", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/incidents/remediation", Handler: "API.handleIncidentRemediation", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/audit", Handler: "API.handleAudit", Console: true},
	{Path: "/allowlist/suggestions", Handler: "API.handleAllowlistSuggestions", Console: true},
	{Path: "/allowlist", Handler: "API.handleAllowlistAdd", Console: true, MutatingMethods: []string{"POST"}, ConsoleMethods: []string{"DELETE"}},
	{Path: "/egress/uninspected", Handler: "API.handleUninspectedEgress", Console: true},
	{Path: "/egress/endpoint", Handler: "API.handleEndpointDetail", Console: true},
	{Path: "/egress/episodes", Handler: "API.handleEgressEpisodes", Console: true, NoAgent: true},
	{Path: "/egress/episodes/", Handler: "API.handleEgressEpisodeSubpath", Prefix: true, Leaves: []Leaf{{Path: "assess"}}, Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/expected-egress", Handler: "API.handleExpectedEgress", Console: true, NoAgent: true, MutatingMethods: []string{"POST", "DELETE"}},
	{Path: "/notify/rules", Handler: "API.handleNotifyRules", Console: true, ConsoleMethods: []string{"POST"}},
	{Path: "/guard/path-allow", Handler: "API.handleGuardPathAllow", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/mute", Handler: "API.handleMute", Console: true, MutatingMethods: []string{"POST"}, ConsoleMethods: []string{"DELETE"}},
	{Path: "/expected", Handler: "API.handleExpected", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}, ConsoleMethods: []string{"DELETE"}},
	{Path: "/advisor/retriage", Handler: "API.handleAdvisorRetriage", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/advisor/assess-host", Handler: "API.handleAdvisorAssessHost", Console: true, ConsoleMethods: []string{"POST"}},
	{Path: "/flags/acknowledge", Handler: "API.handleFlagAcknowledge", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/patterns", Handler: "API.handlePatterns", Response: "[]model.Pattern", Console: true},
	{Path: "/firewall/patterns", Handler: "API.handleFirewallPatterns", NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/guard/config", Handler: "API.handleGuardConfig", NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/ui/open-fda", Handler: "API.handleOpenFDA", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/ui/open-config", Handler: "API.handleOpenConfig", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/stats/rollup", Handler: "API.handleRollup", Console: true},
	{Path: "/costs", Handler: "API.handleCosts", Response: "store.CostReport", Console: true},
	{Path: "/costs/unpriced", Handler: "API.handleCostsUnpriced", Console: true},
	{Path: "/costs/plans", Handler: "API.handleCostsPlans", Console: true},
	{Path: "/doctor", Handler: "API.handleDoctor", Response: "api.DoctorReport", Console: true},
	{Path: "/coverage/probe", Handler: "API.handleCoverageProbe", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/routing/claude", Handler: "API.handleRoutingClaude", NoAgent: true},
	{Path: "/worktrees", Handler: "API.handleWorktrees", Console: true, NoAgent: true},
	{Path: "/worktrees/repos", Handler: "API.handleWorktreeRepos", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/worktrees/remove", Handler: "API.handleWorktreeRemove", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/worktrees/advise", Handler: "API.handleWorktreeAdvise", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/worktrees/reveal", Handler: "API.handleWorktreeReveal", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/worktrees/reconnect", Handler: "API.handleWorktreeReconnect", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/worktrees/trash", Handler: "API.handleWorktreeTrash", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/worktrees/review-trash", Handler: "API.handleWorktreeReviewTrash", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/cleanup/ledger", Handler: "API.handleCleanupLedger", Console: true, NoAgent: true},
	{Path: "/worktrees/ask", Handler: "API.handleWorktreeAsk", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/worktrees/asks", Handler: "API.handleWorktreeAsks", Console: true, NoAgent: true},
	{Path: "/cleanup", Handler: "API.handleCleanup", Console: true, NoAgent: true},
	{Path: "/cleanup/trash", Handler: "API.handleCleanupTrash", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/cleanup/clean", Handler: "API.handleCleanupClean", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/cleanup/advise", Handler: "API.handleCleanupAdvise", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/advisor/discover", Handler: "API.handleAdvisorDiscover"},
	{Path: "/fleet", Handler: "API.handleFleet", Response: "api.FleetNodeStatus", Console: true},
	{Path: "/kill", Handler: "API.handleKill", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/firewall/mode", Handler: "API.handleFirewallMode", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/firewall/fingerprints/reload", Handler: "API.handleFingerprintReload", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/firewall/fingerprints/ingest", Handler: "API.handleFingerprintIngest", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/firewall/sources", Handler: "API.handleFirewallSources", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/guard/decision", Handler: "API.handleGuardDecision", Decide: true},
	{Path: "/guard/pending", Handler: "API.handleGuardPending", Console: true},
	{Path: "/guard/resolve", Handler: "API.handleGuardResolve", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/guard/rules", Handler: "API.handleGuardRules", Console: true, MutatingMethods: []string{"POST"}},
	{Path: "/debug/pprof/", Handler: "handlePprof", Prefix: true, Console: false, OwnerOnly: true},
	{Path: "/files/detail", Handler: "API.handleFileDetail", Response: "model.FileDetail", Console: true, NoAgent: true},
	{Path: "/files/reveal", Handler: "API.handleFileReveal", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/files/open", Handler: "API.handleFileOpen", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/advisor/plan", Handler: "API.handleAdvisorPlan", Response: "api.PlanResponse", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/labels", Handler: "API.handleLabels", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	// The system agent (console Agent tab): chat, plans and dispatch. NoAgent
	// throughout — a harness dispatch must never be reachable by an agent.
	{Path: "/agent/status", Handler: "API.handleAgentStatus", Console: true, NoAgent: true},
	{Path: "/agent/skills", Handler: "API.handleAgentSkills", Console: true, NoAgent: true},
	{Path: "/agent/chat", Handler: "API.handleAgentChat", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}, ConsoleMethods: []string{"DELETE"}},
	{Path: "/agent/analyze", Handler: "API.handleAgentAnalyze", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/agent/recommendations", Handler: "API.handleAgentRecommendations", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/agent/worktree", Handler: "API.handleAgentWorktree", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/agent/actions", Handler: "API.handleAgentActions", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/agent/plans", Handler: "API.handleAgentPlans", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}, ConsoleMethods: []string{"DELETE"}},
	{Path: "/agent/dispatch", Handler: "API.handleAgentDispatch", Console: true, NoAgent: true, MutatingMethods: []string{"POST"}},
	{Path: "/agent/runs", Handler: "API.handleAgentRuns", Console: true, NoAgent: true},
}

// ConsoleAllowed reports whether the console token admits (method, path) on
// the proxy listener. Exact table paths are admitted directly; a dynamic
// family (/sessions/{id}/timeline, /sessions/{id}/report,
// /sessions/{id}/memory, /flags/{id}/explain)
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
			matched = len(parts) == 2 && parts[0] != "" && parts[0] != "." && parts[0] != ".." && slices.ContainsFunc(r.Leaves, func(leaf Leaf) bool { return leaf.Path == parts[1] })
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
		if !routeMatches(r, path) {
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
		if routeMatches(r, path) {
			return r.NoAgent
		}
	}
	return false
}

func routeMatches(r Route, path string) bool {
	if !r.Prefix {
		return r.Path == path
	}
	if !strings.HasPrefix(path, r.Path) {
		return false
	}
	rest := strings.TrimPrefix(path, r.Path)
	parts := strings.SplitN(rest, "/", 2)
	return len(parts) == 2 && parts[0] != "" && parts[0] != "." && parts[0] != ".." && slices.ContainsFunc(r.Leaves, func(leaf Leaf) bool { return leaf.Path == parts[1] })
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
