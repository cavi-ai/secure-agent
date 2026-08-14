package api

import (
	"encoding/json"
	"net/http"
	"os"
	"runtime"
)

type FleetNodeStatus struct {
	Hostname      string         `json:"hostname"`
	OS            string         `json:"os"`
	Arch          string         `json:"arch"`
	Version       string         `json:"version"`
	Running       bool           `json:"running"`
	Uptime        string         `json:"uptime"`
	ActiveAgents  int            `json:"active_agents"`
	Agents        []AgentSummary `json:"agents"`
	RecentFlags   int            `json:"recent_flags"`
	ProxyEnabled  bool           `json:"proxy_enabled"`
	ProxyPort     int            `json:"proxy_port"`
	TailnetReady bool           `json:"tailnet_ready"`
}

func (a *API) handleFleet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "macOS-Local"
	}

	st := a.statusFn()
	flags := a.store.RecentFlags(100)

	node := FleetNodeStatus{
		Hostname:      hostname,
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		Version:       "v1.0.0",
		Running:       st.Running,
		Uptime:        st.Uptime,
		ActiveAgents:  st.ActiveAgents,
		Agents:        st.Agents,
		RecentFlags:   len(flags),
		ProxyEnabled:  st.ProxyEnabled,
		ProxyPort:     st.ProxyPort,
		TailnetReady: true,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(node)
}
