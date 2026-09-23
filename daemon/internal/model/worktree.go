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
