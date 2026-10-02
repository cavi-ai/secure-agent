package api

import "net/http"

// RoutingInfo is what the menu bar app writes into Claude Code's user
// settings to route it through the proxy: Env for Claude Code's own process
// (inspect mode, with the proxy CA), and BashEnvPath, the tunnel-mode snippet
// a SessionStart hook appends to each session's Bash environment.
type RoutingInfo struct {
	Ready       bool              `json:"ready"`
	Reason      string            `json:"reason,omitempty"`
	Env         map[string]string `json:"env,omitempty"`
	BashEnvPath string            `json:"bash_env_path,omitempty"`
}

// handleRoutingClaude serves GET /routing/claude. NoAgent: the answer carries
// the proxy token.
func (a *API) handleRoutingClaude(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.routing == nil {
		writeJSON(w, RoutingInfo{Reason: "routing is not wired"})
		return
	}
	writeJSON(w, a.routing())
}
