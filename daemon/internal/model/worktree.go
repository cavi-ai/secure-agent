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
	Action string    `json:"action"` // worktree-remove | worktree-prune
	Path   string    `json:"path"`
	Repo   string    `json:"repo,omitempty"`
	Bytes  int64     `json:"bytes"`
	Detail string    `json:"detail,omitempty"`
}

// CleanupTotals sums the ledger: all time and the last 30 days.
type CleanupTotals struct {
	Bytes    int64 `json:"bytes"`
	Count    int   `json:"count"`
	Bytes30d int64 `json:"bytes_30d"`
	Count30d int   `json:"count_30d"`
}
