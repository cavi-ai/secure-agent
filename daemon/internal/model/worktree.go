package model

import "time"

// WorktreeRepo is one repository on the worktree hunter's saved list.
// Path is the main worktree (or the bare repository directory).
type WorktreeRepo struct {
	Path string `json:"path"`
	// Source says how the repo was first found: session (an agent worked
	// in it), scan (a well-known worktree directory), root (a configured
	// scan root) or manual (added by the operator). Manual wins over the
	// others on later sightings.
	Source    string    `json:"source"`
	FirstSeen time.Time `json:"first_seen"`
	LastScan  time.Time `json:"last_scan,omitempty"`
	// Hidden repos stay on the list but are left out of reports.
	Hidden bool `json:"hidden,omitempty"`
}

// Worktree repo sources.
const (
	RepoSourceSession = "session"
	RepoSourceScan    = "scan"
	RepoSourceRoot    = "root"
	RepoSourceManual  = "manual"
)

// WorkspaceActivity is the session record for one workspace directory: the
// newest last_seen across its sessions and whether any is still live.
type WorkspaceActivity struct {
	Workspace string
	LastSeen  time.Time
	Live      bool
}

// WorktreeAdviceRequest is what the local advisor sees for one worktree:
// the checker's verdict and the repository data behind it. Branch, reasons,
// paths and commit subjects come from the repository and are untrusted.
type WorktreeAdviceRequest struct {
	Path     string   `json:"path"`
	Head     string   `json:"head"`
	Branch   string   `json:"branch,omitempty"`
	State    string   `json:"state"`
	IdleDays int      `json:"idle_days"`
	Reasons  []string `json:"reasons,omitempty"`
	Paths    []string `json:"paths,omitempty"`
	Precious []string `json:"precious,omitempty"`
	Commits  []string `json:"commits,omitempty"` // subjects of commits on no remote and not in the default branch
}

// CleanupEntry is one row of the cleanup ledger: what was removed, where,
// and how many bytes it gave back. The ledger is what "reclaimed" totals
// and the history of tidying the machine read from.
type CleanupEntry struct {
	ID     int64     `json:"id"`
	TS     time.Time `json:"ts"`
	Action string    `json:"action"` // worktree-remove | worktree-prune | trash:<kind> | clean:<tool> | ask:<verdict>
	Path   string    `json:"path"`
	Repo   string    `json:"repo,omitempty"`
	Bytes  int64     `json:"bytes"`
	Detail string    `json:"detail,omitempty"`
}

// CleanupTotals sums the ledger: all time and the last 30 days. Moves to
// the Trash are counted apart (Trashed*): their space frees only when the
// Trash is emptied.
type CleanupTotals struct {
	TrashedBytes int64 `json:"trashed_bytes"`
	TrashedCount int   `json:"trashed_count"`
	Bytes        int64 `json:"bytes"`
	Count        int   `json:"count"`
	Bytes30d     int64 `json:"bytes_30d"`
	Count30d     int   `json:"count_30d"`
}

// CleanupDay sums one calendar day of the ledger (the daemon's local
// time) like CleanupTotals: bytes freed and the cleanups that freed them,
// moves to the Trash apart.
type CleanupDay struct {
	Day          string `json:"day"` // YYYY-MM-DD
	Bytes        int64  `json:"bytes"`
	Count        int    `json:"count"`
	TrashedBytes int64  `json:"trashed_bytes"`
	TrashedCount int    `json:"trashed_count"`
}

// AgentAsk is one request to the agent that owns a worktree: resume its
// conversation and have it open a pull request for work worth keeping or
// say the worktree can go. The record is kept so the machine's tidying
// history includes what agents answered.
type AgentAsk struct {
	ID         int64      `json:"id"`
	TS         time.Time  `json:"ts"`
	Path       string     `json:"path"`
	Repo       string     `json:"repo,omitempty"`
	Harness    string     `json:"harness"`
	SessionID  string     `json:"session_id"`
	Status     string     `json:"status"`            // running | answered | failed | timeout
	Verdict    string     `json:"verdict,omitempty"` // pr | removable | keep | none
	Detail     string     `json:"detail,omitempty"`  // the PR URL or the agent's reason
	CostUSD    float64    `json:"cost_usd,omitempty"`
	Output     string     `json:"output,omitempty"` // the reply's last lines
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// ProjectCleanupRequest is what the local advisor sees for one project's
// recommendation: its worktrees and its clutter as the checkers left them.
// Paths, branches and reasons come from the repository and are untrusted.
type ProjectCleanupRequest struct {
	Project   string            `json:"project"` // repository path, or "machine" for machine-wide caches
	Worktrees []ProjectWorktree `json:"worktrees,omitempty"`
	Clutter   []ProjectClutter  `json:"clutter,omitempty"`
}

// ProjectWorktree is one worktree line of a project request.
type ProjectWorktree struct {
	Path      string   `json:"path"`
	Branch    string   `json:"branch,omitempty"`
	State     string   `json:"state"`
	SizeBytes int64    `json:"size_bytes,omitempty"`
	IdleDays  int      `json:"idle_days"`
	Reasons   []string `json:"reasons,omitempty"`
}

// ProjectClutter is one clutter line of a project request.
type ProjectClutter struct {
	Kind      string `json:"kind"`
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes,omitempty"`
	IdleDays  int    `json:"idle_days"`
	Action    string `json:"action"`
}
