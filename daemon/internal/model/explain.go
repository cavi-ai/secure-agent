package model

import "time"

// FlagExplain is the daemon's plain-language reading of one flag: what
// happened, the file and destinations involved, the session it happened in,
// one disposition, and the actions that apply. Built at serve time from the
// stored evidence, the session spine, the endpoint identity table and the
// allowlist; never persisted.
type FlagExplain struct {
	What        string          `json:"what"`
	Subject     *ExplainSubject `json:"subject,omitempty"`
	Egress      []ExplainEgress `json:"egress,omitempty"`
	Context     *ExplainContext `json:"context,omitempty"`
	Disposition Disposition     `json:"disposition"`
	Actions     []ExplainAction `json:"actions"`
}

// ExplainSubject is the file a flag is about (read, keychain and transcript
// evidence).
type ExplainSubject struct {
	Path          string `json:"path"`
	Display       string `json:"display"`
	Basename      string `json:"basename"`
	Category      string `json:"category"`
	CategoryLabel string `json:"category_label"`
	Rule          string `json:"rule,omitempty"`
	OwnerLabel    string `json:"owner_label"`
}

// ExplainEgress is one destination a flag cites, deduped by host:port.
type ExplainEgress struct {
	Host string `json:"host"`
	Port int    `json:"port,omitempty"`
	Org  string `json:"org,omitempty"`
	Name string `json:"name,omitempty"`
	Kind string `json:"kind"`
	// Allowlisted: the operator already approved this host for the flag's
	// agent (evaluated at serve time).
	Allowlisted bool `json:"allowlisted"`
	// GapSeconds is connect time minus read time; negative when the
	// connection preceded the read, 0 when the flag has no read item.
	GapSeconds float64 `json:"gap_seconds"`
}

// ExplainContext is the session the flag happened in and the tool call and
// model nearest the flagged moment.
type ExplainContext struct {
	SessionID  string     `json:"session_id,omitempty"`
	Harness    string     `json:"harness,omitempty"`
	Repo       string     `json:"repo,omitempty"`
	Branch     string     `json:"branch,omitempty"`
	Workspace  string     `json:"workspace,omitempty"`
	Tool       string     `json:"tool,omitempty"`
	ToolStatus string     `json:"tool_status,omitempty"`
	ToolAt     *time.Time `json:"tool_at,omitempty"`
	Model      string     `json:"model,omitempty"`
}

// Disposition is the one verdict every surface renders for a flag.
type Disposition struct {
	State string `json:"state"` // acknowledged | benign-likely | warning | critical
	Text  string `json:"text"`
	Why   string `json:"why"`
}

// Disposition states.
const (
	DispositionAcknowledged = "acknowledged"
	DispositionBenignLikely = "benign-likely"
	DispositionWarning      = "warning"
	DispositionCritical     = "critical"
)

// ExplainAction is one operator action that applies to the flag, served with
// the exact request that performs it.
type ExplainAction struct {
	ID          string         `json:"id"`
	Label       string         `json:"label"`
	Consequence string         `json:"consequence"`
	Method      string         `json:"method"`
	Path        string         `json:"path"`
	Body        map[string]any `json:"body,omitempty"`
	Recommended bool           `json:"recommended,omitempty"`
}
