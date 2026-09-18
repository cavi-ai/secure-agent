package model

// NodeStatus is the periodic fleet heartbeat payload: liveness plus the
// node's own posture headline, so a collector can answer "is anything
// critical anywhere, and is every node alive?" without re-deriving posture
// from raw flags. Sent on a ticker AND immediately on posture-state
// transitions; it flows to every configured sink regardless of the sink's
// event-kind filter (liveness must not be unsubscribable).
type NodeStatus struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Agents   int    `json:"agents"`
	Uptime   string `json:"uptime,omitempty"`
	// Posture mirrors the daemon's /posture headline (api.Posture), duplicated
	// here as plain fields so the fleet package stays free of an api import.
	PostureState   string `json:"posture_state"` // all-clear | attention | critical
	PostureSummary string `json:"posture_summary"`
	NeedsYou       int    `json:"needs_you"`
	// Labels are operator-defined dimensions (env, role, team…) from
	// fleet.labels in config.yaml — the grouping key for multi-fleet views.
	Labels map[string]string `json:"labels,omitempty"`
	// Budget is the node's resource-budget posture (counts only): which mode
	// is in force and how many sessions are over budget, awaiting approval,
	// contained, or paused. Lets a fleet view answer "which node is enforcing
	// a budget" without fetching every node's resource detail.
	Budget *BudgetStatus `json:"budget,omitempty"`
}

// BudgetStatus is the compact per-node budget posture carried in heartbeats.
type BudgetStatus struct {
	Mode       string `json:"mode"` // observe | prompt | terminate
	Enforced   bool   `json:"enforced"`
	OverBudget int    `json:"over_budget"`
	Approval   int    `json:"approval"`
	Contained  int    `json:"contained"`
	Paused     int    `json:"paused"`
}
