package posture

import (
	"github.com/cavi-ai/secure-agent/daemon/internal/hookhealth"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// Posture is the single headline answer: "do I need to look at this machine,
// and what is the one thing to look at first?" Every UI (console, menubar,
// fleet collector) renders from this instead of re-deriving it from raw lists.
//
// Invariant: every pending decision in Items appears in exactly one Group,
// and group item counts sum to NeedsYou (= len(Items)). CoverageItems retain
// active faults, configuration notes and historical gaps. CoverageCount counts
// only active faults; historical gaps do not claim current delivery is failing.
type Posture struct {
	State         string        `json:"state"` // all-clear | attention | critical
	NeedsYou      int           `json:"needs_you"`
	CoverageCount int           `json:"coverage_count"`
	Summary       string        `json:"summary"`
	Items         []PostureItem `json:"items"`
	CoverageItems []PostureItem `json:"coverage_items"`
	// Groups is the session-grouped attention queue every surface renders;
	// agent-less items sit in the "machine" group.
	Groups           []AttentionGroup  `json:"groups,omitempty"`
	Generated        string            `json:"generated"`
	Connected        bool              `json:"connected"`
	AttentionSummary *AttentionSummary `json:"attention_summary,omitempty"`
}

// AttentionItem priorities (higher first): guard 5, resource 4, incident 3,
// critical flag, pattern and routine 2.
type AttentionItem struct {
	Kind            string                `json:"kind"` // resource | guard | incident | flag | pattern | routine
	Priority        int                   `json:"priority"`
	ID              string                `json:"id,omitempty"`
	Action          string                `json:"action,omitempty"`
	Title           string                `json:"title"`
	Detail          string                `json:"detail,omitempty"`
	Rule            string                `json:"rule,omitempty"`
	Path            string                `json:"path,omitempty"`
	Tool            string                `json:"tool,omitempty"`
	Workspace       string                `json:"workspace,omitempty"`
	ScopeText       string                `json:"scopeText,omitempty"`
	AvailableScopes []model.ScopeChoice   `json:"available_scopes,omitempty"`
	ReaderExe       string                `json:"reader_exe,omitempty"`
	Status          string                `json:"status,omitempty"`
	Count           int                   `json:"count,omitempty"`
	Hosts           []string              `json:"hosts,omitempty"`
	Advisor         *model.AdvisorVerdict `json:"advisor,omitempty"`
	// Disposition is set on flag items (the same verdict /flags/{id}/explain
	// serves) and pattern items (the worst open flag's).
	Disposition  *model.Disposition           `json:"disposition,omitempty"`
	Assessment   *model.FindingAssessment     `json:"assessment,omitempty"`
	Review       *model.ReviewRecord          `json:"review,omitempty"`
	SessionID    string                       `json:"session_id,omitempty"`
	HookFinding  *hookhealth.Finding          `json:"hook_finding,omitempty"`
	HookDelivery *store.HookForwarderSnapshot `json:"hook_delivery,omitempty"`
}

// AttentionGroup is one agent session, an explicit unattributed bucket, or
// the machine group (Key "machine") for signals no agent owns, with its
// pending decisions, worst first.
type AttentionGroup struct {
	Key          string  `json:"key"`
	Label        string  `json:"label"`
	Agent        string  `json:"agent"`
	Workspace    string  `json:"workspace,omitempty"`
	RootPID      int32   `json:"rootPid,omitempty"`
	PIDs         []int32 `json:"pids,omitempty"`
	RSSBytes     uint64  `json:"rssBytes,omitempty"`
	CPUPercent   float64 `json:"cpuPercent,omitempty"`
	ProcessCount int     `json:"processCount,omitempty"`
	// Summary, on an agent-level group (Key "agent:…"), names the processes
	// and sessions behind its findings and whether they still run.
	Summary string          `json:"summary,omitempty"`
	Items   []AttentionItem `json:"items"`
}

// AttentionSummary is an additive presentation of the existing queue. Queued
// counts still sum to needs_you; coverage gaps are counted separately.
type AttentionSummary struct {
	Version int               `json:"version"`
	Buckets []AttentionBucket `json:"buckets"`
}

type AttentionBucket struct {
	Kind          string              `json:"kind"`
	Count         int                 `json:"count"`
	CoverageCount int                 `json:"coverage_count"`
	First         *AttentionReference `json:"first,omitempty"`
}

// AttentionReference points to an existing group item, never a new authority
// to approve access or a substitute for the item's current evidence.
type AttentionReference struct {
	Kind      string `json:"kind"`
	ID        string `json:"id"`
	Title     string `json:"title"`
	SessionID string `json:"session_id,omitempty"`
}
